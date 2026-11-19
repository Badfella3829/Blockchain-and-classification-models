// Dashboard data client: TanStack Query options around the app's server functions.
import { queryOptions } from "@tanstack/react-query";
import {
  exportChain,
  getAlerts,
  getBlocks,
  getDashboardMetrics,
  getIncidents,
  getModelHealth,
  runSimulation,
  updateIncidentStatus,
  verifyChain,
} from "@/lib/threat/threat.functions";
import type { IncidentSort, IncidentStatus, Severity } from "@/lib/threat/types";

export type Interval = number | false;

export type IncidentFilters = {
  severity: Severity | "All";
  status: IncidentStatus | "All";
  search: string;
  sort: IncidentSort;
  order: "asc" | "desc";
  page: number;
  pageSize: number;
};

export const DEFAULT_FILTERS: IncidentFilters = {
  severity: "All",
  status: "All",
  search: "",
  sort: "block_index",
  order: "desc",
  page: 1,
  pageSize: 10,
};

export const toIncidentQuery = (filters: IncidentFilters) => ({
  page: filters.page,
  pageSize: filters.pageSize,
  sort: filters.sort,
  order: filters.order,
  ...(filters.severity !== "All" ? { severity: filters.severity } : {}),
  ...(filters.status !== "All" ? { status: filters.status } : {}),
  ...(filters.search.trim() ? { search: filters.search.trim() } : {}),
});

/** Keeps search input to characters the server accepts. */
export const cleanSearch = (value: string) => value.replace(/[^\w .:-]/g, "").slice(0, 60);

export const metricsQuery = (interval: Interval) =>
  queryOptions({
    queryKey: ["threat", "metrics"],
    queryFn: () => getDashboardMetrics(),
    refetchInterval: interval,
    retry: 1,
  });

export const incidentsQuery = (filters: IncidentFilters, interval: Interval) =>
  queryOptions({
    queryKey: ["threat", "incidents", filters],
    queryFn: () => getIncidents({ data: toIncidentQuery(filters) }),
    refetchInterval: interval,
    placeholderData: (previous) => previous,
    retry: 1,
  });

export const blocksQuery = (page: number, pageSize: number, interval: Interval) =>
  queryOptions({
    queryKey: ["threat", "blocks", page, pageSize],
    queryFn: () => getBlocks({ data: { page, pageSize } }),
    refetchInterval: interval,
    placeholderData: (previous) => previous,
    retry: 1,
  });

export const alertsQuery = (since: string | null, interval: Interval) =>
  queryOptions({
    queryKey: ["threat", "alerts", since],
    queryFn: () => getAlerts({ data: { since } }),
    refetchInterval: interval,
    retry: 1,
  });

export const modelHealthQuery = (interval: Interval) =>
  queryOptions({
    queryKey: ["threat", "model-health"],
    queryFn: async () => {
      if (typeof window !== "undefined") {
        const response = await fetch("/api/model/health", {
          headers: { accept: "application/json" },
        });
        if (!response.ok) {
          const text = await response.text().catch(() => "");
          throw new Error(text || `Model health request failed (${response.status}).`);
        }
        return (await response.json()) as Awaited<ReturnType<typeof getModelHealth>>;
      }
      return getModelHealth();
    },
    refetchInterval: interval,
    retry: 1,
  });

export type StatusChangeResponse =
  { ok: true; blockIndex: number; status: IncidentStatus } | { ok: false; message: string };

/** Calls POST /api/incidents/{id}/status to append a status_change block on the ledger. */
export async function postIncidentStatus(input: {
  id: string;
  status: IncidentStatus;
  by: string;
}): Promise<StatusChangeResponse> {
  const response = await fetch(`/api/incidents/${encodeURIComponent(input.id)}/status`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ status: input.status, by: input.by }),
  });
  const payload = (await response.json().catch(() => null)) as StatusChangeResponse | null;
  if (!payload) {
    return { ok: false, message: `Status change failed (${response.status}).` };
  }
  return payload;
}

/** Every incident matching the current filters (for CSV export). */
export async function fetchAllIncidents(filters: IncidentFilters) {
  const items = [];
  for (let page = 1; page <= 10; page += 1) {
    const result = await getIncidents({
      data: toIncidentQuery({ ...filters, page, pageSize: 1000 }),
    });
    items.push(...result.items);
    if (items.length >= result.total || result.items.length === 0) break;
  }
  return items;
}

export function downloadJson(data: unknown, filename: string) {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }),
  );
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

export type FlowAnalysisResponse =
  | {
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
      signals: { feature: string; value: number; zScore: number }[];
    }
  | { ok: false; message: string };

/** Calls POST /api/predict to score a network flow against the deployed Random Forest. */
export async function analyzeFlow(input: {
  features: Record<string, number | string | null>;
  source?: string;
  category?: string;
  recordToLedger?: boolean;
}): Promise<FlowAnalysisResponse> {
  const response = await fetch("/api/predict", {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify(input),
  });
  const payload = (await response.json().catch(() => null)) as FlowAnalysisResponse | null;
  if (!payload) {
    return { ok: false, message: `Flow analysis failed (${response.status}).` };
  }
  return payload;
}

export const api = {
  runSimulation,
  verifyChain,
  updateIncidentStatus,
  exportChain,
  postIncidentStatus,
  analyzeFlow,
};
