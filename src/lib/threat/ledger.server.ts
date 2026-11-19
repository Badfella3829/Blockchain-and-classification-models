// Server-only: ledger storage, scoring and simulation backed by Supabase Postgres.
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@/integrations/supabase/types";
import { GENESIS_EVENT, hashBlock, verifyBlocks } from "./canonical";
import { ATTACK_THRESHOLD, severityFor } from "./severity";
import { detectDrift } from "./drift";
import type {
  AlertFeed,
  BlockPage,
  ChainVerification,
  IncidentSort,
  IncidentStatus,
  ModelHealth,
  StatusChangeEvent,
  DashboardMetrics,
  DetectionEvent,
  Incident,
  IncidentPage,
  JsonValue,
  LedgerBlock,
  ModelInfo,
  Severity,
  SimulationResult,
} from "./types";
import { SEVERITIES } from "./types";
import { predictProbability, type FeatureRecord, type WebModelBundle } from "./web-model";
import modelText from "./model/web-model.json?raw";
import simulationRowsText from "./model/simulation-rows.json?raw";

type Db = SupabaseClient<Database>;

// Loaded once per worker, not per request.
const MODEL = JSON.parse(modelText) as WebModelBundle;
const SIMULATION_ROWS = JSON.parse(simulationRowsText) as {
  features: FeatureRecord;
  category: string;
  expected_probability: number;
}[];

export const LIMITS = {
  maxEventsPerSimulation: 20,
  simulationsPerMinute: 10,
  maxBlocks: 5000,
} as const;

export function modelInfo(): ModelInfo {
  const metrics = (MODEL.metrics ?? {}) as {
    selected_model?: string;
    evaluation?: string;
    trained_at?: string;
    models?: Record<string, DashboardMetrics["model"]["scores"]>;
  };
  const selected = metrics.selected_model ?? "Random Forest";
  return {
    modelVersion: MODEL.model_version,
    selectedModel: selected,
    evaluation: metrics.evaluation ?? "unknown",
    trainedAt: metrics.trained_at ?? "",
    features: MODEL.features,
    scores: metrics.models?.[selected] ?? null,
  };
}

export function scoreRecord(record: FeatureRecord) {
  const unknown = Object.keys(record).filter((key) => !MODEL.features.includes(key));
  if (unknown.length) throw new Error(`Unknown feature(s): ${unknown.join(", ")}`);
  const probability = predictProbability(MODEL, record);
  return {
    probability,
    isAttack: probability >= ATTACK_THRESHOLD,
    severity: severityFor(probability),
  };
}

// ---------------------------------------------------------------------------
// Ledger
// ---------------------------------------------------------------------------
type BlockRow = Database["public"]["Tables"]["chain_blocks"]["Row"];

const toBlock = (row: BlockRow): LedgerBlock => ({
  index: row.block_index,
  timestamp: row.timestamp,
  event: row.event as JsonValue,
  previous_hash: row.previous_hash,
  hash: row.hash,
});

async function tip(db: Db): Promise<LedgerBlock | null> {
  const { data, error } = await db
    .from("chain_blocks")
    .select("*")
    .order("block_index", { ascending: false })
    .limit(1)
    .maybeSingle();
  if (error) throw new Error(`Could not read the ledger: ${error.message}`);
  return data ? toBlock(data) : null;
}

const isConflict = (error: { code?: string } | null) => error?.code === "23505";

/** Creates the genesis block when the ledger is empty (safe to call repeatedly). */
export async function ensureGenesis(admin: Db) {
  if (await tip(admin)) return;
  const block = {
    index: 1,
    timestamp: new Date().toISOString(),
    event: GENESIS_EVENT,
    previous_hash: "0",
  };
  const hash = await hashBlock(block);
  const { error } = await admin.from("chain_blocks").insert({
    block_index: 1,
    timestamp: block.timestamp,
    event: GENESIS_EVENT,
    previous_hash: "0",
    hash,
  });
  if (error && !isConflict(error))
    throw new Error(`Could not create the genesis block: ${error.message}`);
}

/**
 * Appends blocks linked to the current tip in one insert. The unique block
 * index / previous-hash constraints reject a writer racing for the same slot,
 * so on conflict we re-read the tip and rebuild the batch instead of forking.
 */
export async function appendBlocks(
  admin: Db,
  events: (DetectionEvent | StatusChangeEvent)[],
  attempts = 8,
): Promise<LedgerBlock[]> {
  if (events.length === 0) return [];
  await ensureGenesis(admin);
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const last = await tip(admin);
    if (!last) throw new Error("Ledger has no genesis block.");
    const built: LedgerBlock[] = [];
    let previous = last;
    for (const event of events) {
      const block = {
        index: previous.index + 1,
        timestamp: new Date().toISOString(),
        event: event as JsonValue,
        previous_hash: previous.hash,
      };
      previous = { ...block, hash: await hashBlock(block) };
      built.push(previous);
    }
    const { error } = await admin.from("chain_blocks").insert(
      built.map((block) => ({
        block_index: block.index,
        timestamp: block.timestamp,
        event: block.event as Database["public"]["Tables"]["chain_blocks"]["Insert"]["event"],
        previous_hash: block.previous_hash,
        hash: block.hash,
      })),
    );
    if (!error) return built;
    if (!isConflict(error)) throw new Error(`Could not append to the ledger: ${error.message}`);
    await new Promise((resolve) => setTimeout(resolve, 15 + Math.random() * 60));
  }
  throw new Error("The ledger is busy; please try again.");
}

export async function appendBlock(
  admin: Db,
  event: DetectionEvent | StatusChangeEvent,
): Promise<LedgerBlock> {
  const [block] = await appendBlocks(admin, [event]);
  return block!;
}

export async function allBlocks(db: Db): Promise<LedgerBlock[]> {
  const blocks: LedgerBlock[] = [];
  const pageSize = 1000;
  for (let from = 0; ; from += pageSize) {
    const { data, error } = await db
      .from("chain_blocks")
      .select("*")
      .order("block_index", { ascending: true })
      .range(from, from + pageSize - 1);
    if (error) throw new Error(`Could not read the ledger: ${error.message}`);
    blocks.push(...data.map(toBlock));
    if (data.length < pageSize) return blocks;
  }
}

export async function verifyLedger(db: Db): Promise<ChainVerification> {
  const blocks = await allBlocks(db);
  const result = await verifyBlocks(blocks);
  return { ...result, length: blocks.length, checkedAt: new Date().toISOString() };
}

export async function recentBlocks(db: Db, limit: number): Promise<LedgerBlock[]> {
  const { data, error } = await db
    .from("chain_blocks")
    .select("*")
    .order("block_index", { ascending: false })
    .limit(limit);
  if (error) throw new Error(`Could not read the ledger: ${error.message}`);
  return data.map(toBlock);
}

// ---------------------------------------------------------------------------
// Incidents and metrics
// ---------------------------------------------------------------------------
type IncidentRowDb = Database["public"]["Views"]["incident_view"]["Row"];

const toIncident = (row: IncidentRowDb): Incident => ({
  type: "detection",
  event_id: row.event_id ?? "",
  source: row.source ?? "unknown",
  category: row.category ?? "Unclassified",
  severity: (row.severity ?? "Low") as Severity,
  confidence: Number(row.confidence ?? 0),
  model_version: row.model_version ?? "unknown",
  status: (row.status ?? "Open") as IncidentStatus,
  blockIndex: row.block_index ?? 0,
  detectedAt: row.detected_at ?? "",
  hash: row.hash ?? "",
  previousHash: row.previous_hash ?? "",
  statusBlockIndex: row.status_block_index,
  statusChangedAt: row.status_changed_at,
  statusChangedBy: row.status_changed_by,
});

const SORT_COLUMNS: Record<IncidentSort, keyof IncidentRowDb> = {
  block_index: "block_index",
  detected_at: "block_index",
  confidence: "confidence",
  severity: "severity_rank",
  source: "source",
  category: "category",
  status: "status",
  event_id: "event_id",
};

export async function listIncidents(
  db: Db,
  options: {
    severity?: Severity;
    status?: string;
    search?: string;
    sort?: IncidentSort;
    order?: "asc" | "desc";
    page: number;
    pageSize: number;
  },
): Promise<IncidentPage> {
  const sortColumn = SORT_COLUMNS[options.sort ?? "block_index"];
  let query = db
    .from("incident_view")
    .select("*", { count: "exact" })
    .order(sortColumn, { ascending: options.order === "asc" });
  if (sortColumn !== "block_index") query = query.order("block_index", { ascending: false });
  if (options.severity) query = query.eq("severity", options.severity);
  if (options.status) query = query.eq("status", options.status);
  const search = options.search?.trim();
  if (search) {
    const term = `*${search}*`;
    query = query.or(
      ["event_id", "source", "category"].map((field) => `${field}.ilike.${term}`).join(","),
    );
  }
  const from = (options.page - 1) * options.pageSize;
  const { data, error, count } = await query.range(from, from + options.pageSize - 1);
  if (error) throw new Error(`Could not read incidents: ${error.message}`);
  return {
    items: data.map(toIncident),
    total: count ?? 0,
    page: options.page,
    pageSize: options.pageSize,
  };
}

export async function getIncident(db: Db, id: string): Promise<Incident | null> {
  const { data, error } = await db
    .from("incident_view")
    .select("*")
    .eq("event_id", id)
    .maybeSingle();
  if (error) throw new Error(`Could not read the incident: ${error.message}`);
  return data ? toIncident(data) : null;
}

export async function alertsSince(db: Db, since: string | null): Promise<AlertFeed> {
  let query = db
    .from("incident_view")
    .select("*", { count: "exact" })
    .in("severity", ["Critical", "High"])
    .order("block_index", { ascending: false });
  if (since) query = query.gt("detected_at", since);
  const { data, error, count } = await query.limit(8);
  if (error) throw new Error(`Could not read alerts: ${error.message}`);
  return { unread: count ?? 0, items: data.map(toIncident) };
}

export async function listBlocks(db: Db, page: number, pageSize: number): Promise<BlockPage> {
  const from = (page - 1) * pageSize;
  const { data, error, count } = await db
    .from("chain_blocks")
    .select("*", { count: "exact" })
    .order("block_index", { ascending: false })
    .range(from, from + pageSize - 1);
  if (error) throw new Error(`Could not read the ledger: ${error.message}`);
  return { items: data.map(toBlock), total: count ?? 0, page, pageSize };
}

/** Appends a status_change block; the ledger is append-only, so rows are never updated. */
export async function changeIncidentStatus(
  admin: Db,
  id: string,
  status: IncidentStatus,
  by: string,
) {
  const incident = await getIncident(admin, id);
  if (!incident) return { ok: false as const, message: `Incident ${id} was not found.` };
  if (incident.status === status)
    return { ok: false as const, message: `Incident ${id} is already ${status}.` };
  if ((await countBlocks(admin)) >= LIMITS.maxBlocks) {
    return { ok: false as const, message: `The ledger is full (${LIMITS.maxBlocks} blocks).` };
  }
  const block = await appendBlock(admin, {
    type: "status_change",
    incident_id: id,
    new_status: status,
    by,
  });
  return { ok: true as const, blockIndex: block.index, status };
}

export async function dashboardMetrics(db: Db): Promise<DashboardMetrics> {
  const [summary, traffic] = await Promise.all([
    db.rpc("threat_summary"),
    db.rpc("traffic_series", { _hours: 24, _bucket_hours: 2 }),
  ]);
  if (summary.error) throw new Error(`Could not read metrics: ${summary.error.message}`);
  if (traffic.error) throw new Error(`Could not read traffic: ${traffic.error.message}`);
  const s = summary.data as {
    events_analyzed: number;
    threats_detected: number;
    critical_open: number;
    open_incidents: number;
    avg_confidence: number | null;
    severity_counts: Partial<Record<Severity, number>>;
    chain_length: number;
  };
  const total = s.threats_detected;
  return {
    eventsAnalyzed: s.events_analyzed,
    threatsDetected: total,
    avgConfidence: s.avg_confidence === null ? null : Number(s.avg_confidence),
    criticalOpen: s.critical_open,
    openIncidents: s.open_incidents,
    chainLength: s.chain_length,
    severitySummary: SEVERITIES.map((label) => {
      const count = s.severity_counts[label] ?? 0;
      return { label, count, percent: total ? Math.round((count * 100) / total) : 0 };
    }),
    traffic: traffic.data.map((row) => ({
      time: new Date(row.bucket_start).toISOString().slice(11, 16),
      events: Number(row.events),
      threats: Number(row.threats),
    })),
    model: modelInfo(),
  };
}

type RawMetrics = {
  dataset?: string;
  dataset_kind?: "synthetic" | "real";
  artifact_bytes?: number;
  web_artifact_bytes?: number;
  train_rows?: number;
  test_rows?: number;
  selected_model?: string;
  models?: Record<
    string,
    {
      accuracy: number;
      precision: number;
      recall: number;
      f1: number;
      confusion_matrix: number[][];
    }
  >;
  feature_importances?: { feature: string; importance: number }[];
};

export async function modelHealth(db: Db): Promise<ModelHealth> {
  const metrics = (MODEL.metrics ?? {}) as RawMetrics;
  const info = modelInfo();
  const { data, error } = await db.rpc("model_live_stats");
  if (error) throw new Error(`Could not read live model stats: ${error.message}`);
  const live = data as {
    predictions_today: number;
    attacks_today: number;
    avg_attack_confidence: number | null;
    recent_count: number;
    recent_attacks: number;
    earlier_count: number;
    earlier_attacks: number;
  };
  const models = metrics.models ?? {};
  return {
    info,
    datasetKind:
      metrics.dataset_kind ?? (metrics.dataset?.includes("synthetic") ? "synthetic" : "real"),
    dataset: metrics.dataset ?? "unknown",
    artifactBytes: metrics.artifact_bytes ?? null,
    webArtifactBytes: metrics.web_artifact_bytes ?? null,
    testRows: metrics.test_rows ?? null,
    trainRows: metrics.train_rows ?? null,
    comparison: Object.entries(models).map(([model, m]) => ({
      model,
      accuracy: m.accuracy,
      precision: m.precision,
      recall: m.recall,
      f1: m.f1,
    })),
    confusionMatrix: models[metrics.selected_model ?? "Random Forest"]?.confusion_matrix ?? null,
    featureImportances: (metrics.feature_importances ?? []).slice(0, 10),
    live: {
      predictionsToday: live.predictions_today,
      attacksToday: live.attacks_today,
      attackRateToday: live.predictions_today
        ? (live.attacks_today * 100) / live.predictions_today
        : null,
      avgAttackConfidence:
        live.avg_attack_confidence === null ? null : Number(live.avg_attack_confidence),
      drift: detectDrift(
        { n: live.recent_count, attacks: live.recent_attacks },
        { n: live.earlier_count, attacks: live.earlier_attacks },
      ),
    },
  };
}

// ---------------------------------------------------------------------------
// Prediction and simulation
// ---------------------------------------------------------------------------
const randomId = () => crypto.randomUUID().replace(/-/g, "").slice(0, 8).toUpperCase();
const randomSource = () =>
  `10.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${1 + Math.floor(Math.random() * 254)}`;

function detectionEvent(
  probability: number,
  severity: Severity,
  meta: { source?: string; category?: string },
): DetectionEvent {
  return {
    type: "detection",
    event_id: `SIG-${randomId()}`,
    source: meta.source ?? "unknown",
    category: meta.category ?? "Unclassified",
    severity,
    confidence: Math.round(probability * 10000) / 100,
    model_version: MODEL.model_version,
    status: "Open",
  };
}

export async function predictAndRecord(
  admin: Db,
  record: FeatureRecord,
  meta: { source?: string; category?: string } = {},
) {
  const { probability, isAttack, severity } = scoreRecord(record);
  if (isAttack && (await countBlocks(admin)) >= LIMITS.maxBlocks) {
    throw new Error(`The ledger is full (${LIMITS.maxBlocks} blocks).`);
  }
  const { error } = await admin
    .from("predictions")
    .insert({ is_attack: isAttack, probability, severity });
  if (error) throw new Error(`Could not save the prediction: ${error.message}`);
  const block = isAttack
    ? await appendBlock(admin, detectionEvent(probability, severity, meta))
    : null;
  return {
    label: isAttack ? "Attack" : "Normal",
    probability: Math.round(probability * 10000) / 10000,
    severity,
    recorded: isAttack,
    blockIndex: block?.index ?? null,
  };
}

async function countBlocks(db: Db) {
  const { count, error } = await db
    .from("chain_blocks")
    .select("block_index", { count: "exact", head: true });
  if (error) throw new Error(`Could not count ledger blocks: ${error.message}`);
  return count ?? 0;
}

/** Per-visitor limit kept in the database (workers keep no memory between requests). */
async function checkRateLimit(admin: Db, clientKey: string): Promise<SimulationResult | null> {
  const windowStart = new Date(Date.now() - 60_000).toISOString();
  await admin
    .from("simulation_requests")
    .delete()
    .lt("created_at", new Date(Date.now() - 3_600_000).toISOString());
  const { data, error } = await admin
    .from("simulation_requests")
    .select("created_at")
    .eq("client_key", clientKey)
    .gte("created_at", windowStart)
    .order("created_at", { ascending: true });
  if (error) throw new Error(`Could not check the simulation limit: ${error.message}`);
  if (data.length >= LIMITS.simulationsPerMinute) {
    const oldest = new Date(data[0]!.created_at).getTime();
    const retryAfterSeconds = Math.max(1, Math.ceil((oldest + 60_000 - Date.now()) / 1000));
    return {
      ok: false,
      status: 429,
      message: `Too many simulations: up to ${LIMITS.simulationsPerMinute} runs per minute. Try again in ${retryAfterSeconds}s.`,
      retryAfterSeconds,
    };
  }
  const insert = await admin.from("simulation_requests").insert({ client_key: clientKey });
  if (insert.error) throw new Error(`Could not record the simulation: ${insert.error.message}`);
  return null;
}

export async function runSimulation(
  admin: Db,
  clientKey: string,
  count: number,
): Promise<SimulationResult> {
  const limited = await checkRateLimit(admin, clientKey);
  if (limited) return limited;
  await ensureGenesis(admin);
  const blocks = await countBlocks(admin);
  if (blocks >= LIMITS.maxBlocks) {
    return {
      ok: false,
      status: 429,
      message: `The ledger is full (${LIMITS.maxBlocks} blocks). No more events can be recorded.`,
    };
  }
  const room = LIMITS.maxBlocks - blocks;
  const scored = [];
  let attacks = 0;
  let capped = false;
  for (let i = 0; i < count; i += 1) {
    const row = SIMULATION_ROWS[Math.floor(Math.random() * SIMULATION_ROWS.length)]!;
    const score = scoreRecord(row.features);
    if (score.isAttack) {
      if (attacks >= room) {
        capped = true;
        break;
      }
      attacks += 1;
    }
    scored.push({ ...score, category: row.category });
  }
  const predictions = await admin.from("predictions").insert(
    scored.map((s) => ({
      is_attack: s.isAttack,
      probability: s.probability,
      severity: s.severity,
    })),
  );
  if (predictions.error)
    throw new Error(`Could not save predictions: ${predictions.error.message}`);
  await appendBlocks(
    admin,
    scored
      .filter((s) => s.isAttack)
      .map((s) =>
        detectionEvent(s.probability, s.severity, { source: randomSource(), category: s.category }),
      ),
  );
  return { ok: true, processed: scored.length, attacks, normal: scored.length - attacks, capped };
}
