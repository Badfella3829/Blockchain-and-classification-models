import type { Incident, IncidentStatus, Severity } from "@/lib/threat/types";

/** What the incident table & detail drawer show, for both live ledger records and the offline demo set. */
export type IncidentRow = {
  id: string;
  title: string;
  source: string;
  category: string;
  severity: Severity;
  confidence: number;
  detectedAt: string;
  firstSeen: string;
  status: IncidentStatus;
  description: string;
  blockIndex: number | null;
  hash: string | null;
  previousHash: string | null;
  modelVersion: string | null;
  statusBlockIndex: number | null;
  statusChangedAt: string | null;
  statusChangedBy: string | null;
};

export function relativeTime(iso: string, now = Date.now()): string {
  if (!iso) return "—";
  const parsed = new Date(iso).getTime();
  if (Number.isNaN(parsed)) return iso;
  const seconds = Math.max(0, Math.round((now - parsed) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours} h ago`;
  return new Date(iso).toLocaleDateString();
}

export function formatBytes(bytes: number | null): string {
  if (bytes === null || !Number.isFinite(bytes)) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function shortHash(hash: string, prefix = 6, suffix = 6): string {
  if (hash.length <= prefix + suffix + 1) return hash;
  return `${hash.slice(0, prefix)}…${hash.slice(-suffix)}`;
}

export function toIncidentRow(incident: Incident): IncidentRow {
  return {
    id: incident.event_id,
    title: `${incident.category} activity detected`,
    source: incident.source,
    category: incident.category,
    severity: incident.severity,
    confidence: incident.confidence,
    detectedAt: incident.detectedAt,
    firstSeen: relativeTime(incident.detectedAt),
    status: incident.status,
    description: `The Random Forest model scored this traffic record as an attack with ${incident.confidence.toFixed(
      1,
    )}% confidence. The detection is recorded in ledger block #${incident.blockIndex}, cryptographically linked by SHA-256 hash to the previous block.`,
    blockIndex: incident.blockIndex,
    hash: incident.hash,
    previousHash: incident.previousHash,
    modelVersion: incident.model_version,
    statusBlockIndex: incident.statusBlockIndex,
    statusChangedAt: incident.statusChangedAt,
    statusChangedBy: incident.statusChangedBy,
  };
}

export function downloadIncidents(rows: IncidentRow[], filename = "sentinel-incidents.csv") {
  const columns: Array<keyof IncidentRow> = [
    "id",
    "title",
    "source",
    "category",
    "severity",
    "confidence",
    "detectedAt",
    "status",
    "blockIndex",
    "hash",
    "previousHash",
    "modelVersion",
    "statusBlockIndex",
    "statusChangedBy",
  ];
  const csv = [
    columns.join(","),
    ...rows.map((row) =>
      columns.map((column) => `"${String(row[column] ?? "").replace(/"/g, '""')}"`).join(","),
    ),
  ].join("\n");
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}
