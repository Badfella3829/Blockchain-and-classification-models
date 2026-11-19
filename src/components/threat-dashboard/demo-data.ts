// Offline fallback only: shown with a "Demo data" badge when the live API cannot be reached.
import type {
  IncidentSort,
  IncidentStatus,
  LedgerBlock,
  ModelHealth,
  Severity,
} from "@/lib/threat/types";
import type { IncidentRow } from "./incident-rows";

type DemoIncident = {
  id: string;
  title: string;
  source: string;
  category: string;
  severity: Severity;
  confidence: number;
  firstSeen: string;
  status: IncidentStatus;
  description: string;
  blockIndex: number;
  hash: string;
  previousHash: string;
};

const demoIncidents: DemoIncident[] = [
  {
    id: "SIG-1042",
    title: "Repeated SSH authentication failures",
    source: "10.28.4.17",
    category: "Credential abuse",
    severity: "Critical",
    confidence: 99.2,
    firstSeen: "2 min ago",
    status: "Open",
    description:
      "A burst of failed sign-in attempts was observed against an internal service. Shown as offline demo fallback because the live API could not be reached.",
    blockIndex: 7,
    hash: "8f2a9c41d3e71b220987654321abcdef0123456789abcdef0123456789aac91d",
    previousHash: "7bc41234abcd5678ef90123456789abcdef0123456789abcdef0123456782a60",
  },
  {
    id: "SIG-1039",
    title: "DNS request to a newly registered domain",
    source: "172.20.2.9",
    category: "DNS anomaly",
    severity: "High",
    confidence: 96.4,
    firstSeen: "8 min ago",
    status: "Open",
    description:
      "An endpoint requested a domain with a recently observed registration pattern. Review the associated process and DNS context before taking action.",
    blockIndex: 6,
    hash: "7bc41234abcd5678ef90123456789abcdef0123456789abcdef0123456782a60",
    previousHash: "2de98765fedc4321ba0987654321fedcba9876543210fedcba98765432104f17",
  },
  {
    id: "SIG-1035",
    title: "Unusual outbound data transfer",
    source: "10.28.7.22",
    category: "Network anomaly",
    severity: "High",
    confidence: 93.8,
    firstSeen: "14 min ago",
    status: "Contained",
    description:
      "Outbound traffic volume exceeded the sample baseline for this asset. Marked as contained in the offline demo fallback set.",
    blockIndex: 5,
    hash: "2de98765fedc4321ba0987654321fedcba9876543210fedcba98765432104f17",
    previousHash: "4ab192837465abcd1234ef567890abcd1234ef567890abcd1234ef5678909e01",
  },
  {
    id: "SIG-1031",
    title: "Privilege escalation behavior",
    source: "10.28.4.31",
    category: "Endpoint activity",
    severity: "Medium",
    confidence: 88.1,
    firstSeen: "26 min ago",
    status: "Open",
    description:
      "A process requested permissions outside the example host profile. Included in the offline fallback dataset.",
    blockIndex: 4,
    hash: "4ab192837465abcd1234ef567890abcd1234ef567890abcd1234ef5678909e01",
    previousHash: "91cd00112233445566778899aabbccddeeff00112233445566778899aabb3321",
  },
  {
    id: "SIG-1028",
    title: "Suspicious script execution pattern",
    source: "10.28.3.14",
    category: "Process behavior",
    severity: "Medium",
    confidence: 84.6,
    firstSeen: "41 min ago",
    status: "Open",
    description:
      "Matched a behavior heuristic for an unusual script launch in the offline fallback dataset.",
    blockIndex: 3,
    hash: "91cd00112233445566778899aabbccddeeff00112233445566778899aabb3321",
    previousHash: "50ef99887766554433221100ffeeddccbbaa99887766554433221100ffee77a2",
  },
  {
    id: "SIG-1022",
    title: "Unexpected internal service discovery",
    source: "10.28.8.51",
    category: "Network anomaly",
    severity: "Low",
    confidence: 71.3,
    firstSeen: "58 min ago",
    status: "Contained",
    description:
      "An internal asset made a sequence of service requests that differed from the illustrative baseline.",
    blockIndex: 2,
    hash: "50ef99887766554433221100ffeeddccbbaa99887766554433221100ffee77a2",
    previousHash: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  },
];

export const incidentData: IncidentRow[] = demoIncidents.map((incident) => ({
  ...incident,
  detectedAt: "",
  modelVersion: "rf-offline-demo",
  statusBlockIndex: null,
  statusChangedAt: null,
  statusChangedBy: null,
}));

const SEVERITY_RANK: Record<Severity, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
};

export function filterIncidents(
  rows: IncidentRow[],
  searchTerm: string,
  severity: Severity | "All",
  status: IncidentStatus | "All" = "All",
) {
  const query = searchTerm.trim().toLowerCase();
  return rows.filter((incident) => {
    const matchesSeverity = severity === "All" || incident.severity === severity;
    const matchesStatus = status === "All" || incident.status === status;
    const matchesSearch =
      !query ||
      [incident.id, incident.title, incident.source, incident.category, incident.severity].some(
        (value) => value.toLowerCase().includes(query),
      );
    return matchesSeverity && matchesStatus && matchesSearch;
  });
}

export function sortIncidentRows(
  rows: IncidentRow[],
  sort: IncidentSort,
  order: "asc" | "desc",
): IncidentRow[] {
  const dir = order === "asc" ? 1 : -1;
  return [...rows].sort((a, b) => {
    let cmp = 0;
    switch (sort) {
      case "block_index":
      case "detected_at":
        cmp = (a.blockIndex ?? 0) - (b.blockIndex ?? 0);
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
        cmp = a.id.localeCompare(b.id);
        break;
    }
    return cmp * dir;
  });
}

export const trafficSeries = [
  { time: "00:00", events: 165, threats: 2 },
  { time: "02:00", events: 142, threats: 1 },
  { time: "04:00", events: 218, threats: 3 },
  { time: "06:00", events: 194, threats: 2 },
  { time: "08:00", events: 286, threats: 4 },
  { time: "10:00", events: 248, threats: 3 },
  { time: "12:00", events: 372, threats: 7 },
  { time: "14:00", events: 314, threats: 5 },
  { time: "16:00", events: 428, threats: 9 },
  { time: "18:00", events: 356, threats: 6 },
  { time: "20:00", events: 468, threats: 12 },
  { time: "22:00", events: 392, threats: 8 },
];

export const severitySummary: { label: Severity; count: number; percent: number }[] = [
  { label: "Critical", count: 3, percent: 4 },
  { label: "High", count: 12, percent: 18 },
  { label: "Medium", count: 31, percent: 46 },
  { label: "Low", count: 22, percent: 32 },
];

export const auditPreview = [
  { id: "BLK-00842", event: "Detection batch recorded", time: "10:42:18", hash: "8f2a…c91d" },
  { id: "BLK-00841", event: "Model score attached", time: "10:39:52", hash: "7bc4…2a60" },
  { id: "BLK-00840", event: "Signal policy updated", time: "10:31:06", hash: "2de9…4f17" },
];

export const demoBlocks: LedgerBlock[] = [
  ...demoIncidents.map((inc) => ({
    index: inc.blockIndex,
    timestamp: "2026-11-19T08:00:00.000Z",
    event: {
      type: "detection",
      event_id: inc.id,
      source: inc.source,
      category: inc.category,
      severity: inc.severity,
      confidence: inc.confidence,
      model_version: "rf-offline-demo",
      status: inc.status,
    },
    previous_hash: inc.previousHash,
    hash: inc.hash,
  })),
  {
    index: 1,
    timestamp: "2026-11-19T07:00:00.000Z",
    event: "Genesis Block",
    previous_hash: "0",
    hash: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  },
];

export const demoModelHealth: ModelHealth = {
  info: {
    modelVersion: "rf-offline-demo",
    selectedModel: "Random Forest",
    evaluation: "offline fallback metrics",
    trainedAt: "2026-11-19T08:01:53.732501+00:00",
    features: [
      "dur",
      "proto",
      "service",
      "state",
      "spkts",
      "dpkts",
      "sbytes",
      "dbytes",
      "rate",
      "sttl",
    ],
    scores: {
      accuracy: 0.962,
      precision: 0.9628,
      recall: 0.9681,
      f1: 0.9654,
      confusion_matrix: [
        [863, 41],
        [35, 1061],
      ],
    },
  },
  datasetKind: "synthetic",
  dataset: "synthetic_training-set.csv",
  artifactBytes: 1241451,
  webArtifactBytes: 520438,
  trainRows: 6000,
  testRows: 2000,
  comparison: [
    { model: "Random Forest", accuracy: 0.962, precision: 0.9628, recall: 0.9681, f1: 0.9654 },
    {
      model: "Logistic Regression",
      accuracy: 0.9545,
      precision: 0.9539,
      recall: 0.9635,
      f1: 0.9587,
    },
    { model: "Naive Bayes", accuracy: 0.939, precision: 0.9468, recall: 0.9416, f1: 0.9442 },
  ],
  confusionMatrix: [
    [863, 41],
    [35, 1061],
  ],
  featureImportances: [
    { feature: "dbytes", importance: 0.28007 },
    { feature: "sttl", importance: 0.18556 },
    { feature: "dpkts", importance: 0.142183 },
    { feature: "dload", importance: 0.099977 },
    { feature: "dmean", importance: 0.092536 },
    { feature: "dttl", importance: 0.079018 },
    { feature: "state", importance: 0.02456 },
    { feature: "spkts", importance: 0.021062 },
    { feature: "dur", importance: 0.014162 },
    { feature: "sload", importance: 0.014083 },
  ],
  live: {
    predictionsToday: 0,
    attacksToday: 0,
    attackRateToday: null,
    avgAttackConfidence: null,
    drift: {
      status: "insufficient",
      recentRate: null,
      baselineRate: null,
      message: "Live drift telemetry is unavailable while offline.",
    },
  },
};
