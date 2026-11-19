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
  queryOptions({ queryKey: ["threat", "metrics"], queryFn: () => getDashboardMetrics(), refetchInterval: interval, retry: 1 });

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
  queryOptions({ queryKey: ["threat", "model-health"], queryFn: () => getModelHealth(), refetchInterval: interval, retry: 1 });

/** Every incident matching the current filters (for CSV export). */
export async function fetchAllIncidents(filters: IncidentFilters) {
  const items = [];
  for (let page = 1; page <= 10; page += 1) {
    const result = await getIncidents({ data: toIncidentQuery({ ...filters, page, pageSize: 1000 }) });
    items.push(...result.items);
    if (items.length >= result.total || result.items.length === 0) break;
  }
  return items;
}

export function downloadJson(data: unknown, filename: string) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

export const api = { runSimulation, verifyChain, updateIncidentStatus, exportChain };
