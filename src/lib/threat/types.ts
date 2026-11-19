export type Severity = "Critical" | "High" | "Medium" | "Low";
export type IncidentStatus = "Open" | "Contained";
export const SEVERITIES: Severity[] = ["Critical", "High", "Medium", "Low"];

/** Event stored inside a ledger block for every detected attack. */
export type DetectionEvent = {
  type: "detection";
  event_id: string;
  source: string;
  category: string;
  severity: Severity;
  confidence: number;
  model_version: string;
  status: IncidentStatus;
};

export type JsonValue =
  string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

export type LedgerBlock = {
  index: number;
  timestamp: string;
  event: JsonValue;
  previous_hash: string;
  hash: string;
};

export type Incident = DetectionEvent & {
  blockIndex: number;
  detectedAt: string;
  hash: string;
  previousHash: string;
  statusBlockIndex: number | null;
  statusChangedAt: string | null;
  statusChangedBy: string | null;
};

export type StatusChangeEvent = {
  type: "status_change";
  incident_id: string;
  new_status: IncidentStatus;
  by: string;
};

export const INCIDENT_SORTS = [
  "block_index",
  "detected_at",
  "confidence",
  "severity",
  "source",
  "category",
  "status",
  "event_id",
] as const;
export type IncidentSort = (typeof INCIDENT_SORTS)[number];

export type BlockPage = { items: LedgerBlock[]; total: number; page: number; pageSize: number };

export type AlertFeed = { unread: number; items: Incident[] };

export type ModelHealth = {
  info: ModelInfo;
  datasetKind: "synthetic" | "real";
  dataset: string;
  artifactBytes: number | null;
  webArtifactBytes: number | null;
  testRows: number | null;
  trainRows: number | null;
  comparison: { model: string; accuracy: number; precision: number; recall: number; f1: number }[];
  confusionMatrix: number[][] | null;
  featureImportances: { feature: string; importance: number }[];
  live: {
    predictionsToday: number;
    attacksToday: number;
    attackRateToday: number | null;
    avgAttackConfidence: number | null;
    drift: DriftResult;
  };
};

export type DriftResult = {
  status: "ok" | "warning" | "insufficient";
  recentRate: number | null;
  baselineRate: number | null;
  message: string;
};

export type ModelScores = {
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
  confusion_matrix: number[][];
};

export type ModelInfo = {
  modelVersion: string;
  selectedModel: string;
  evaluation: string;
  trainedAt: string;
  features: string[];
  scores: ModelScores | null;
};

export type DashboardMetrics = {
  eventsAnalyzed: number;
  threatsDetected: number;
  avgConfidence: number | null;
  criticalOpen: number;
  openIncidents: number;
  chainLength: number;
  severitySummary: { label: Severity; count: number; percent: number }[];
  traffic: { time: string; events: number; threats: number }[];
  model: ModelInfo;
};

export type ChainVerification = {
  valid: boolean;
  length: number;
  badIndex: number | null;
  reason: string | null;
  checkedAt: string;
};

export type IncidentPage = {
  items: Incident[];
  total: number;
  page: number;
  pageSize: number;
};

export type SimulationResult =
  | { ok: true; processed: number; attacks: number; normal: number; capped: boolean }
  | { ok: false; status: 429 | 503; message: string; retryAfterSeconds?: number };
