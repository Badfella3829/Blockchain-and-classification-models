// Local persistent ledger fallback when SUPABASE_URL is not configured.
// Uses the exact same Random Forest web-model, SHA-256 canonical block hashing,
// append-only status_change derivation, and drift logic as ledger.server.ts.
import { GENESIS_EVENT, hashBlock, verifyBlocks } from "./canonical";
import { detectDrift } from "./drift";
import { ATTACK_THRESHOLD, severityFor } from "./severity";
import type {
  AlertFeed,
  BlockPage,
  ChainVerification,
  DashboardMetrics,
  DetectionEvent,
  Incident,
  IncidentPage,
  IncidentSort,
  IncidentStatus,
  JsonValue,
  LedgerBlock,
  ModelHealth,
  ModelInfo,
  Severity,
  SimulationResult,
  StatusChangeEvent,
} from "./types";
import { SEVERITIES } from "./types";
import { predictProbability, type FeatureRecord, type WebModelBundle } from "./web-model";
import modelText from "./model/web-model.json?raw";
import simulationRowsText from "./model/simulation-rows.json?raw";

const MODEL = JSON.parse(modelText) as WebModelBundle;
const SIMULATION_ROWS = JSON.parse(simulationRowsText) as {
  features: FeatureRecord;
  category: string;
  expected_probability: number;
}[];

export const LOCAL_LIMITS = {
  maxEventsPerSimulation: 20,
  simulationsPerMinute: 10,
  maxBlocks: 5000,
} as const;

type PredictionRecord = {
  createdAt: string;
  isAttack: boolean;
  probability: number;
  severity: Severity;
};

type PersistedState = {
  blocks: LedgerBlock[];
  predictions: PredictionRecord[];
  rateHits: Record<string, number[]>;
};

const SEVERITY_RANK: Record<Severity, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
};

const SEED_SOURCES = [
  "10.28.4.17",
  "10.28.7.22",
  "10.28.14.8",
  "10.28.3.41",
  "172.20.2.9",
  "10.28.11.63",
  "10.28.6.105",
  "10.28.9.19",
];

type GlobalWithLedger = typeof globalThis & {
  __sentinelLocalLedgerPromise?: Promise<PersistedState>;
};

async function loadFromDisk(): Promise<PersistedState | null> {
  try {
    const fs = await import(/* @vite-ignore */ "node:fs/promises");
    const path = await import(/* @vite-ignore */ "node:path");
    const file = path.resolve(process.cwd(), ".data/sentinel-ledger.json");
    const raw = await fs.readFile(file, "utf8");
    const parsed = JSON.parse(raw) as Partial<PersistedState>;
    if (
      Array.isArray(parsed.blocks) &&
      parsed.blocks.length > 0 &&
      Array.isArray(parsed.predictions)
    ) {
      return {
        blocks: parsed.blocks,
        predictions: parsed.predictions,
        rateHits: parsed.rateHits && typeof parsed.rateHits === "object" ? parsed.rateHits : {},
      };
    }
  } catch {
    // Disk persistence unavailable or not yet initialized.
  }
  return null;
}

async function saveToDisk(state: PersistedState): Promise<void> {
  try {
    const fs = await import(/* @vite-ignore */ "node:fs/promises");
    const path = await import(/* @vite-ignore */ "node:path");
    const dir = path.resolve(process.cwd(), ".data");
    await fs.mkdir(dir, { recursive: true });
    const tmp = path.resolve(dir, "sentinel-ledger.json.tmp");
    const target = path.resolve(dir, "sentinel-ledger.json");
    await fs.writeFile(tmp, JSON.stringify(state, null, 2), "utf8");
    await fs.rename(tmp, target);
  } catch {
    // Running in a non-Node runtime (e.g. Cloudflare Worker) or read-only FS.
  }
}

export async function createSeededLedgerState(nowMs = Date.now()): Promise<PersistedState> {
  const genesisTs = new Date(nowMs - 22 * 3600_000).toISOString();
  const genesisBase = {
    index: 1,
    timestamp: genesisTs,
    event: GENESIS_EVENT as JsonValue,
    previous_hash: "0",
  };
  const blocks: LedgerBlock[] = [{ ...genesisBase, hash: await hashBlock(genesisBase) }];
  const predictions: PredictionRecord[] = [];

  // Score a deterministic cross-section of real simulation rows through the exported Random Forest.
  const seedCount = Math.min(36, SIMULATION_ROWS.length);
  const step = Math.max(1, Math.floor(SIMULATION_ROWS.length / seedCount));
  let previous = blocks[0]!;
  let detectedCount = 0;

  for (let i = 0; i < seedCount; i += 1) {
    const row = SIMULATION_ROWS[(i * step) % SIMULATION_ROWS.length]!;
    const probability = predictProbability(MODEL, row.features);
    const isAttack = probability >= ATTACK_THRESHOLD;
    const severity = severityFor(probability);
    // Distribute events from ~20 hours ago up to 4 minutes ago.
    const offsetMinutes = Math.round(((seedCount - 1 - i) / Math.max(1, seedCount - 1)) * 1180) + 4;
    const ts = new Date(nowMs - offsetMinutes * 60_000).toISOString();
    predictions.push({ createdAt: ts, isAttack, probability, severity });

    if (isAttack) {
      detectedCount += 1;
      const eventId = `SIG-${(1040 + detectedCount).toString(16).toUpperCase().padStart(4, "0")}${(i + 10).toString(16).toUpperCase().padStart(2, "0")}`;
      const event: DetectionEvent = {
        type: "detection",
        event_id: eventId,
        source: SEED_SOURCES[i % SEED_SOURCES.length]!,
        category: row.category || "Network anomaly",
        severity,
        confidence: Math.round(probability * 10000) / 100,
        model_version: MODEL.model_version,
        status: "Open",
      };
      const nextBase = {
        index: previous.index + 1,
        timestamp: ts,
        event: event as JsonValue,
        previous_hash: previous.hash,
      };
      previous = { ...nextBase, hash: await hashBlock(nextBase) };
      blocks.push(previous);
    }
  }

  // Record one realistic append-only status_change block on an older detection so the audit ledger showcases both event types.
  const olderDetection = blocks.find(
    (b) =>
      typeof b.event === "object" &&
      b.event !== null &&
      !Array.isArray(b.event) &&
      b.event["type"] === "detection",
  );
  if (
    olderDetection &&
    typeof olderDetection.event === "object" &&
    olderDetection.event !== null &&
    !Array.isArray(olderDetection.event)
  ) {
    const incidentId = String(olderDetection.event["event_id"]);
    const statusEvent: StatusChangeEvent = {
      type: "status_change",
      incident_id: incidentId,
      new_status: "Contained",
      by: "SOC Analyst",
    };
    const nextBase = {
      index: previous.index + 1,
      timestamp: new Date(nowMs - 12 * 60_000).toISOString(),
      event: statusEvent as JsonValue,
      previous_hash: previous.hash,
    };
    previous = { ...nextBase, hash: await hashBlock(nextBase) };
    blocks.push(previous);
  }

  return { blocks, predictions, rateHits: {} };
}

async function getState(): Promise<PersistedState> {
  const g = globalThis as GlobalWithLedger;
  if (!g.__sentinelLocalLedgerPromise) {
    g.__sentinelLocalLedgerPromise = (async () => {
      const existing = await loadFromDisk();
      if (existing) return existing;
      const seeded = await createSeededLedgerState();
      await saveToDisk(seeded);
      return seeded;
    })();
  }
  return g.__sentinelLocalLedgerPromise;
}

export function localModelInfo(): ModelInfo {
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

export function localScoreRecord(record: FeatureRecord) {
  const unknown = Object.keys(record).filter((key) => !MODEL.features.includes(key));
  if (unknown.length) throw new Error(`Unknown feature(s): ${unknown.join(", ")}`);
  const probability = predictProbability(MODEL, record);
  return {
    probability,
    isAttack: probability >= ATTACK_THRESHOLD,
    severity: severityFor(probability),
  };
}

/** Pure derivation of incidents from an append-only block chain. */
export function deriveIncidentsFromBlocks(blocks: LedgerBlock[]): Incident[] {
  const latestStatus = new Map<
    string,
    { status: IncidentStatus; blockIndex: number; changedAt: string; by: string }
  >();

  for (const block of blocks) {
    if (typeof block.event !== "object" || block.event === null || Array.isArray(block.event))
      continue;
    if (block.event["type"] === "status_change") {
      const incidentId = String(block.event["incident_id"] ?? "");
      const newStatus = block.event["new_status"] === "Contained" ? "Contained" : "Open";
      const by = String(block.event["by"] ?? "Unknown");
      const current = latestStatus.get(incidentId);
      if (!current || block.index > current.blockIndex) {
        latestStatus.set(incidentId, {
          status: newStatus,
          blockIndex: block.index,
          changedAt: block.timestamp,
          by,
        });
      }
    }
  }

  const incidents: Incident[] = [];
  for (const block of blocks) {
    if (typeof block.event !== "object" || block.event === null || Array.isArray(block.event))
      continue;
    if (block.event["type"] !== "detection") continue;
    const eventId = String(block.event["event_id"] ?? "");
    const statusUpdate = latestStatus.get(eventId);
    const initialStatus: IncidentStatus =
      block.event["status"] === "Contained" ? "Contained" : "Open";
    incidents.push({
      type: "detection",
      event_id: eventId,
      source: String(block.event["source"] ?? "unknown"),
      category: String(block.event["category"] ?? "Unclassified"),
      severity: String(block.event["severity"] ?? "Low") as Severity,
      confidence: Number(block.event["confidence"] ?? 0),
      model_version: String(block.event["model_version"] ?? "unknown"),
      status: statusUpdate ? statusUpdate.status : initialStatus,
      blockIndex: block.index,
      detectedAt: block.timestamp,
      hash: block.hash,
      previousHash: block.previous_hash,
      statusBlockIndex: statusUpdate?.blockIndex ?? null,
      statusChangedAt: statusUpdate?.changedAt ?? null,
      statusChangedBy: statusUpdate?.by ?? null,
    });
  }

  return incidents;
}

export function sortIncidents(
  items: Incident[],
  sort: IncidentSort = "block_index",
  order: "asc" | "desc" = "desc",
): Incident[] {
  const dir = order === "asc" ? 1 : -1;
  return [...items].sort((a, b) => {
    let cmp = 0;
    switch (sort) {
      case "block_index":
      case "detected_at":
        cmp = a.blockIndex - b.blockIndex;
        break;
      case "confidence":
        cmp = a.confidence - b.confidence;
        break;
      case "severity":
        cmp = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
        break;
      case "source":
        cmp = a.source.localeCompare(b.source);
        break;
      case "category":
        cmp = a.category.localeCompare(b.category);
        break;
      case "status":
        cmp = a.status.localeCompare(b.status);
        break;
      case "event_id":
        cmp = a.event_id.localeCompare(b.event_id);
        break;
    }
    if (cmp !== 0) return cmp * dir;
    return b.blockIndex - a.blockIndex;
  });
}

function buildTrafficSeries(
  predictions: PredictionRecord[],
  nowMs = Date.now(),
  hours = 24,
  bucketHours = 2,
) {
  const now = new Date(nowMs);
  now.setUTCMinutes(0, 0, 0);
  const startMs = now.getTime() - hours * 3600_000;
  const bucketCount = Math.floor(hours / bucketHours) + 1;
  const buckets = Array.from({ length: bucketCount }, (_, i) => ({
    time: new Date(startMs + i * bucketHours * 3600_000).toISOString().slice(11, 16),
    events: 0,
    threats: 0,
  }));

  for (const pred of predictions) {
    const t = new Date(pred.createdAt).getTime();
    if (Number.isNaN(t) || t < startMs) continue;
    const slot = Math.min(Math.floor((t - startMs) / (bucketHours * 3600_000)), buckets.length - 1);
    if (slot >= 0) {
      buckets[slot]!.events += 1;
      if (pred.isAttack) buckets[slot]!.threats += 1;
    }
  }
  return buckets;
}

const randomId = () => crypto.randomUUID().replace(/-/g, "").slice(0, 8).toUpperCase();
const randomSource = () =>
  `10.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${1 + Math.floor(Math.random() * 254)}`;

function makeDetectionEvent(
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

async function appendLocalBlocks(
  state: PersistedState,
  events: (DetectionEvent | StatusChangeEvent)[],
): Promise<LedgerBlock[]> {
  if (events.length === 0) return [];
  let previous: LedgerBlock | undefined = state.blocks[state.blocks.length - 1];
  if (!previous) {
    const genesisBase = {
      index: 1,
      timestamp: new Date().toISOString(),
      event: GENESIS_EVENT as JsonValue,
      previous_hash: "0",
    };
    previous = { ...genesisBase, hash: await hashBlock(genesisBase) };
    state.blocks.push(previous);
  }
  const built: LedgerBlock[] = [];
  for (const event of events) {
    const prevBlock: LedgerBlock = previous;
    const base = {
      index: prevBlock.index + 1,
      timestamp: new Date().toISOString(),
      event: event as JsonValue,
      previous_hash: prevBlock.hash,
    };
    const nextBlock: LedgerBlock = { ...base, hash: await hashBlock(base) };
    previous = nextBlock;
    state.blocks.push(nextBlock);
    built.push(nextBlock);
  }
  await saveToDisk(state);
  return built;
}

export async function localDashboardMetrics(): Promise<DashboardMetrics> {
  const state = await getState();
  const incidents = deriveIncidentsFromBlocks(state.blocks);
  const total = incidents.length;
  const counts: Record<Severity, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  let confSum = 0;
  let criticalOpen = 0;
  let openIncidents = 0;

  for (const inc of incidents) {
    counts[inc.severity] = (counts[inc.severity] ?? 0) + 1;
    confSum += inc.confidence;
    if (inc.status === "Open") {
      openIncidents += 1;
      if (inc.severity === "Critical") criticalOpen += 1;
    }
  }

  return {
    eventsAnalyzed: state.predictions.length,
    threatsDetected: total,
    avgConfidence: total ? Math.round((confSum / total) * 100) / 100 : null,
    criticalOpen,
    openIncidents,
    chainLength: state.blocks.length,
    severitySummary: SEVERITIES.map((label) => ({
      label,
      count: counts[label],
      percent: total ? Math.round((counts[label] * 100) / total) : 0,
    })),
    traffic: buildTrafficSeries(state.predictions),
    model: localModelInfo(),
  };
}

export async function localListIncidents(options: {
  severity?: Severity;
  status?: string;
  search?: string;
  sort?: IncidentSort;
  order?: "asc" | "desc";
  page: number;
  pageSize: number;
}): Promise<IncidentPage> {
  const state = await getState();
  let items = deriveIncidentsFromBlocks(state.blocks);
  if (options.severity) items = items.filter((item) => item.severity === options.severity);
  if (options.status) items = items.filter((item) => item.status === options.status);
  const search = options.search?.trim().toLowerCase();
  if (search) {
    items = items.filter(
      (item) =>
        item.event_id.toLowerCase().includes(search) ||
        item.source.toLowerCase().includes(search) ||
        item.category.toLowerCase().includes(search),
    );
  }
  const sorted = sortIncidents(items, options.sort ?? "block_index", options.order ?? "desc");
  const from = (options.page - 1) * options.pageSize;
  return {
    items: sorted.slice(from, from + options.pageSize),
    total: sorted.length,
    page: options.page,
    pageSize: options.pageSize,
  };
}

export async function localGetIncident(id: string): Promise<Incident | null> {
  const state = await getState();
  return deriveIncidentsFromBlocks(state.blocks).find((item) => item.event_id === id) ?? null;
}

export async function localAlertsSince(since: string | null): Promise<AlertFeed> {
  const state = await getState();
  const sinceMs = since ? new Date(since).getTime() : null;
  const matching = deriveIncidentsFromBlocks(state.blocks)
    .filter((item) => item.severity === "Critical" || item.severity === "High")
    .filter((item) =>
      sinceMs === null || Number.isNaN(sinceMs)
        ? true
        : new Date(item.detectedAt).getTime() > sinceMs,
    )
    .sort((a, b) => b.blockIndex - a.blockIndex);
  return { unread: matching.length, items: matching.slice(0, 8) };
}

export async function localListBlocks(page: number, pageSize: number): Promise<BlockPage> {
  const state = await getState();
  const reversed = [...state.blocks].reverse();
  const from = (page - 1) * pageSize;
  return {
    items: reversed.slice(from, from + pageSize),
    total: reversed.length,
    page,
    pageSize,
  };
}

export async function localAllBlocks(): Promise<LedgerBlock[]> {
  const state = await getState();
  return [...state.blocks];
}

export async function localRecentBlocks(limit: number): Promise<LedgerBlock[]> {
  const state = await getState();
  return [...state.blocks].reverse().slice(0, limit);
}

export async function localVerifyLedger(): Promise<ChainVerification> {
  const state = await getState();
  const result = await verifyBlocks(state.blocks);
  return { ...result, length: state.blocks.length, checkedAt: new Date().toISOString() };
}

export async function localChangeIncidentStatus(id: string, status: IncidentStatus, by: string) {
  const state = await getState();
  const incident = deriveIncidentsFromBlocks(state.blocks).find((item) => item.event_id === id);
  if (!incident) return { ok: false as const, message: `Incident ${id} was not found.` };
  if (incident.status === status)
    return { ok: false as const, message: `Incident ${id} is already ${status}.` };
  if (state.blocks.length >= LOCAL_LIMITS.maxBlocks) {
    return {
      ok: false as const,
      message: `The ledger is full (${LOCAL_LIMITS.maxBlocks} blocks).`,
    };
  }
  const [block] = await appendLocalBlocks(state, [
    { type: "status_change", incident_id: id, new_status: status, by },
  ]);
  return { ok: true as const, blockIndex: block!.index, status };
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

export async function localModelHealth(): Promise<ModelHealth> {
  const state = await getState();
  const metrics = (MODEL.metrics ?? {}) as RawMetrics;
  const info = localModelInfo();
  const now = Date.now();
  const dayStart = new Date(now);
  dayStart.setUTCHours(0, 0, 0, 0);
  const dayStartMs = dayStart.getTime();
  const oneHourAgo = now - 3600_000;
  const twentyFiveHoursAgo = now - 25 * 3600_000;

  let predictionsToday = 0;
  let attacksToday = 0;
  let attackProbSum = 0;
  let recentCount = 0;
  let recentAttacks = 0;
  let earlierCount = 0;
  let earlierAttacks = 0;

  for (const p of state.predictions) {
    const t = new Date(p.createdAt).getTime();
    if (Number.isNaN(t)) continue;
    if (t >= dayStartMs) {
      predictionsToday += 1;
      if (p.isAttack) {
        attacksToday += 1;
        attackProbSum += p.probability;
      }
    }
    if (t >= oneHourAgo) {
      recentCount += 1;
      if (p.isAttack) recentAttacks += 1;
    } else if (t >= twentyFiveHoursAgo) {
      earlierCount += 1;
      if (p.isAttack) earlierAttacks += 1;
    }
  }

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
      predictionsToday,
      attacksToday,
      attackRateToday: predictionsToday ? (attacksToday * 100) / predictionsToday : null,
      avgAttackConfidence: attacksToday
        ? Math.round((attackProbSum / attacksToday) * 100 * 100) / 100
        : null,
      drift: detectDrift(
        { n: recentCount, attacks: recentAttacks },
        { n: earlierCount, attacks: earlierAttacks },
      ),
    },
  };
}

export async function localRunSimulation(
  clientKey: string,
  count: number,
): Promise<SimulationResult> {
  const state = await getState();
  const now = Date.now();
  const windowStart = now - 60_000;
  const recentHits = (state.rateHits[clientKey] ?? []).filter((t) => t >= windowStart);
  if (recentHits.length >= LOCAL_LIMITS.simulationsPerMinute) {
    const oldest = recentHits[0]!;
    const retryAfterSeconds = Math.max(1, Math.ceil((oldest + 60_000 - now) / 1000));
    return {
      ok: false,
      status: 429,
      message: `Too many simulations: up to ${LOCAL_LIMITS.simulationsPerMinute} runs per minute. Try again in ${retryAfterSeconds}s.`,
      retryAfterSeconds,
    };
  }
  state.rateHits[clientKey] = [...recentHits, now];

  if (state.blocks.length >= LOCAL_LIMITS.maxBlocks) {
    return {
      ok: false,
      status: 429,
      message: `The ledger is full (${LOCAL_LIMITS.maxBlocks} blocks). No more events can be recorded.`,
    };
  }

  const room = LOCAL_LIMITS.maxBlocks - state.blocks.length;
  const scored: { probability: number; isAttack: boolean; severity: Severity; category: string }[] =
    [];
  let attacks = 0;
  let capped = false;

  for (let i = 0; i < count; i += 1) {
    const row = SIMULATION_ROWS[Math.floor(Math.random() * SIMULATION_ROWS.length)]!;
    const score = localScoreRecord(row.features);
    if (score.isAttack) {
      if (attacks >= room) {
        capped = true;
        break;
      }
      attacks += 1;
    }
    scored.push({ ...score, category: row.category });
  }

  const nowIso = new Date().toISOString();
  for (const s of scored) {
    state.predictions.push({
      createdAt: nowIso,
      isAttack: s.isAttack,
      probability: s.probability,
      severity: s.severity,
    });
  }

  await appendLocalBlocks(
    state,
    scored
      .filter((s) => s.isAttack)
      .map((s) =>
        makeDetectionEvent(s.probability, s.severity, {
          source: randomSource(),
          category: s.category,
        }),
      ),
  );
  if (attacks === 0) await saveToDisk(state);

  return { ok: true, processed: scored.length, attacks, normal: scored.length - attacks, capped };
}

export async function localPredictAndRecord(
  record: FeatureRecord,
  meta: { source?: string; category?: string } = {},
) {
  const state = await getState();
  const { probability, isAttack, severity } = localScoreRecord(record);
  if (isAttack && state.blocks.length >= LOCAL_LIMITS.maxBlocks) {
    throw new Error(`The ledger is full (${LOCAL_LIMITS.maxBlocks} blocks).`);
  }
  state.predictions.push({
    createdAt: new Date().toISOString(),
    isAttack,
    probability,
    severity,
  });
  let blockIndex: number | null = null;
  if (isAttack) {
    const [block] = await appendLocalBlocks(state, [
      makeDetectionEvent(probability, severity, meta),
    ]);
    blockIndex = block?.index ?? null;
  } else {
    await saveToDisk(state);
  }
  return {
    label: isAttack ? "Attack" : "Normal",
    probability: Math.round(probability * 10000) / 10000,
    severity,
    recorded: isAttack,
    blockIndex,
  };
}

export type FlowSignal = {
  feature: string;
  value: number;
  zScore: number;
};

export type AnalyzeFlowResult = {
  ok: true;
  label: "Attack" | "Normal";
  probability: number;
  confidence: number;
  severity: Severity;
  modelVersion: string;
  recorded: boolean;
  eventId: string | null;
  blockIndex: number | null;
  blockHash: string | null;
  signals: FlowSignal[];
};

export async function localAnalyzeFlow(input: {
  features: FeatureRecord;
  source?: string | undefined;
  category?: string | undefined;
  recordToLedger?: boolean | undefined;
}): Promise<AnalyzeFlowResult> {
  const { probability, isAttack, severity } = localScoreRecord(input.features);

  const signals: FlowSignal[] = MODEL.numeric.columns
    .map((column, idx) => {
      const raw = input.features[column];
      const numericVal =
        raw === null || raw === undefined ? MODEL.numeric.medians[idx]! : Number(raw);
      const mean = MODEL.numeric.means[idx] ?? 0;
      const scale = MODEL.numeric.scales[idx] || 1;
      const z = (numericVal - mean) / scale;
      return {
        feature: column,
        value: Math.round(numericVal * 1000) / 1000,
        zScore: Math.round(z * 100) / 100,
      };
    })
    .sort((a, b) => Math.abs(b.zScore) - Math.abs(a.zScore))
    .slice(0, 5);

  let recorded = false;
  let eventId: string | null = null;
  let blockIndex: number | null = null;
  let blockHash: string | null = null;

  if (input.recordToLedger && isAttack) {
    const state = await getState();
    if (state.blocks.length >= LOCAL_LIMITS.maxBlocks) {
      throw new Error(`The ledger is full (${LOCAL_LIMITS.maxBlocks} blocks).`);
    }
    state.predictions.push({
      createdAt: new Date().toISOString(),
      isAttack,
      probability,
      severity,
    });
    const event = makeDetectionEvent(probability, severity, {
      source: input.source?.trim() || "10.28.99.14",
      category: input.category?.trim() || "Custom Flow",
    });
    const [block] = await appendLocalBlocks(state, [event]);
    recorded = true;
    eventId = event.event_id;
    blockIndex = block?.index ?? null;
    blockHash = block?.hash ?? null;
  }

  return {
    ok: true,
    label: isAttack ? "Attack" : "Normal",
    probability: Math.round(probability * 10000) / 10000,
    confidence: Math.round(probability * 1000) / 10,
    severity,
    modelVersion: MODEL.model_version,
    recorded,
    eventId,
    blockIndex,
    blockHash,
    signals,
  };
}
