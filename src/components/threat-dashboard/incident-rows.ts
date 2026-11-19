import type { Incident, Severity } from "@/lib/threat/types";

/** What the incident table shows, for both live ledger records and the offline demo set. */
export type IncidentRow = {
  id: string;
  title: string;
  source: string;
  category: string;
  severity: Severity;
  confidence: number;
  detectedAt: string;
  firstSeen: string;
  status: "Open" | "Contained";
  description: string;
  blockIndex: number | null;
  hash: string | null;
  modelVersion: string | null;
};

export function relativeTime(iso: string, now = Date.now()) {
  const seconds = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours} h ago`;
  return new Date(iso).toLocaleDateString();
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
    )}% confidence. The detection is stored in ledger block #${incident.blockIndex}, linked by hash to the block before it.`,
    blockIndex: incident.blockIndex,
    hash: incident.hash,
    modelVersion: incident.model_version,
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
    "modelVersion",
  ];
  const csv = [
    columns.join(","),
    ...rows.map((row) => columns.map((column) => `"${String(row[column] ?? "").replace(/"/g, '""')}"`).join(",")),
  ].join("\n");
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}
