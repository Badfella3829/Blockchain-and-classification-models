// Offline fallback only: shown with a "Demo data" badge when the live API cannot be reached.
import type { Severity } from "@/lib/threat/types";
import type { IncidentRow } from "./incident-rows";

type DemoIncident = {
  id: string;
  title: string;
  source: string;
  category: string;
  severity: Severity;
  confidence: number;
  firstSeen: string;
  status: "Open" | "Contained";
  description: string;
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
      "A burst of failed sign-in attempts was observed against an internal service. The source is a private network address and all values shown here are illustrative preview data.",
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
      "Outbound traffic volume exceeded the sample baseline for this asset. The preview marks the event as contained; it is not connected to a live response system.",
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
      "A process requested permissions outside the example host profile. This detection is included to demonstrate severity filtering and event inspection.",
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
      "The sample event matched a behavior heuristic for an unusual script launch. No executable or live endpoint data is present in this preview.",
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
      "An internal asset made a sequence of service requests that differed from the illustrative baseline. The event is shown for interface preview only.",
  },
];

export const incidentData: IncidentRow[] = demoIncidents.map((incident) => ({
  ...incident,
  detectedAt: "",
  blockIndex: null,
  hash: null,
  modelVersion: null,
}));

export function filterIncidents(rows: IncidentRow[], searchTerm: string, severity: Severity | "All") {
  const query = searchTerm.trim().toLowerCase();
  return rows.filter((incident) => {
    const matchesSeverity = severity === "All" || incident.severity === severity;
    const matchesSearch =
      !query ||
      [incident.id, incident.title, incident.source, incident.category, incident.severity].some((value) =>
        value.toLowerCase().includes(query),
      );
    return matchesSeverity && matchesSearch;
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
