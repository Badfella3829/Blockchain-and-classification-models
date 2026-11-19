import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Eye,
  FileDown,
  FlaskConical,
  Loader2,
  Play,
  RefreshCw,
  RotateCcw,
  Search,
  X,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { usePreferences } from "@/hooks/use-preferences";
import { useSimulation } from "@/hooks/use-threat-data";
import {
  api,
  cleanSearch,
  DEFAULT_FILTERS,
  fetchAllIncidents,
  incidentsQuery,
  type IncidentFilters,
} from "@/lib/api";
import type { IncidentSort, IncidentStatus, Severity } from "@/lib/threat/types";
import { filterIncidents, incidentData as demoIncidents, sortIncidentRows } from "./demo-data";
import type { IncidentRow } from "./incident-rows";
import { downloadIncidents, toIncidentRow } from "./incident-rows";

const PAGE_SIZE = 10;

type DetectionsViewProps = {
  offline: boolean;
  onSelectIncident: (incident: IncidentRow) => void;
  onOpenAnalyze: () => void;
};

type SortColumn = {
  key: IncidentSort;
  label: string;
  alignRight?: boolean;
};

const COLUMNS: SortColumn[] = [
  { key: "event_id", label: "ID" },
  { key: "category", label: "Category" },
  { key: "source", label: "Source" },
  { key: "severity", label: "Severity" },
  { key: "status", label: "Status" },
  { key: "confidence", label: "Confidence", alignRight: true },
  { key: "block_index", label: "Block", alignRight: true },
  { key: "detected_at", label: "Detected" },
];

export function DetectionsView({ offline, onSelectIncident, onOpenAnalyze }: DetectionsViewProps) {
  const queryClient = useQueryClient();
  const { refetchInterval } = usePreferences();
  const simulation = useSimulation();
  const [searchInput, setSearchInput] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [severity, setSeverity] = useState<Severity | "All">("All");
  const [status, setStatus] = useState<IncidentStatus | "All">("All");
  const [sort, setSort] = useState<IncidentSort>("block_index");
  const [order, setOrder] = useState<"asc" | "desc">("desc");
  const [page, setPage] = useState(1);
  const [exporting, setExporting] = useState(false);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [bulkBusy, setBulkBusy] = useState(false);

  useEffect(() => {
    const id = setTimeout(() => setDebouncedSearch(cleanSearch(searchInput)), 220);
    return () => clearTimeout(id);
  }, [searchInput]);

  useEffect(() => {
    setPage(1);
  }, [debouncedSearch, severity, status, sort, order]);

  const filters: IncidentFilters = useMemo(
    () => ({
      severity,
      status,
      search: debouncedSearch,
      sort,
      order,
      page,
      pageSize: PAGE_SIZE,
    }),
    [severity, status, debouncedSearch, sort, order, page],
  );

  const query = useQuery({
    ...incidentsQuery(filters, refetchInterval),
    enabled: !offline,
  });

  const demoFiltered = useMemo(
    () =>
      sortIncidentRows(filterIncidents(demoIncidents, searchInput, severity, status), sort, order),
    [searchInput, severity, status, sort, order],
  );

  const rows: IncidentRow[] = offline
    ? demoFiltered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)
    : (query.data?.items ?? []).map(toIncidentRow);

  const total = offline ? demoFiltered.length : (query.data?.total ?? 0);
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const hasFilters = severity !== "All" || status !== "All" || Boolean(searchInput.trim());

  const pageIds = useMemo(() => rows.map((row) => row.id), [rows]);
  const allPageSelected = pageIds.length > 0 && pageIds.every((id) => selectedIds.includes(id));

  function toggleRowSelection(id: string) {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id],
    );
  }

  function togglePageSelection() {
    if (allPageSelected) {
      setSelectedIds((prev) => prev.filter((id) => !pageIds.includes(id)));
    } else {
      setSelectedIds((prev) => Array.from(new Set([...prev, ...pageIds])));
    }
  }

  async function handleBulkStatus(targetStatus: IncidentStatus) {
    if (offline || selectedIds.length === 0) return;
    setBulkBusy(true);
    let updated = 0;
    let failed = 0;
    for (const id of selectedIds) {
      try {
        const res = await api.postIncidentStatus({
          id,
          status: targetStatus,
          by: "Security analyst (bulk)",
        });
        if (res.ok) {
          updated += 1;
        } else {
          failed += 1;
        }
      } catch {
        failed += 1;
      }
    }
    setBulkBusy(false);
    setSelectedIds([]);
    await queryClient.invalidateQueries({ queryKey: ["threat"] });
    if (updated > 0) {
      toast.success(`${updated} incident${updated === 1 ? "" : "s"} marked ${targetStatus}`, {
        description:
          failed > 0
            ? `Appended ${updated} status_change blocks (${failed} failed).`
            : `Appended ${updated} immutable status_change block${updated === 1 ? "" : "s"} to the ledger.`,
      });
    } else if (failed > 0) {
      toast.error("Bulk status update failed", {
        description: `Could not update ${failed} selected incidents.`,
      });
    }
  }

  function toggleSort(column: IncidentSort) {
    if (sort === column) {
      setOrder((prev) => (prev === "asc" ? "desc" : "asc"));
    } else {
      setSort(column);
      setOrder(
        column === "confidence" ||
          column === "severity" ||
          column === "block_index" ||
          column === "detected_at"
          ? "desc"
          : "asc",
      );
    }
  }

  function clearFilters() {
    setSearchInput("");
    setDebouncedSearch("");
    setSeverity("All");
    setStatus("All");
    setPage(1);
  }

  async function handleExportCsv() {
    if (offline) {
      if (demoFiltered.length === 0) {
        toast.info("Nothing to export", { description: "No incidents match the current filters." });
        return;
      }
      downloadIncidents(demoFiltered, "sentinel-demo-incidents.csv");
      toast.success(`Exported ${demoFiltered.length} demo incidents`);
      return;
    }
    setExporting(true);
    try {
      const all = await fetchAllIncidents({ ...DEFAULT_FILTERS, ...filters });
      if (all.length === 0) {
        toast.info("Nothing to export", { description: "No incidents match the current filters." });
        return;
      }
      downloadIncidents(all.map(toIncidentRow), "sentinel-detections.csv");
      toast.success(`Exported ${all.length} filtered incidents`);
    } catch (error) {
      toast.error("Export failed", {
        description: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setExporting(false);
    }
  }

  const startItem = total === 0 ? 0 : (page - 1) * PAGE_SIZE + 1;
  const endItem = Math.min(total, page * PAGE_SIZE);

  return (
    <div className="view-stack">
      {offline ? (
        <div className="status-banner status-banner-error" role="alert">
          <AlertTriangle size={16} aria-hidden="true" />
          <p>
            <strong>Offline demo fallback.</strong>{" "}
            <span>Showing sample detections. Status updates require the live API.</span>
          </p>
        </div>
      ) : query.isError ? (
        <div className="status-banner status-banner-error" role="alert">
          <AlertTriangle size={16} aria-hidden="true" />
          <p>
            <strong>Failed to load detections.</strong>{" "}
            <span>
              {query.error instanceof Error ? query.error.message : "Could not reach the ledger."}
            </span>
          </p>
          <Button
            variant="ghost"
            className="action-button"
            type="button"
            onClick={() => void query.refetch()}
          >
            <RefreshCw size={14} aria-hidden="true" /> Retry
          </Button>
        </div>
      ) : null}

      <section className="panel incidents-panel" aria-labelledby="detections-table-title">
        <div className="detections-controls">
          <div className="detections-heading">
            <h2 id="detections-table-title">All detections</h2>
            <p className="tabular-nums">
              {offline
                ? `${total.toLocaleString()} demo detections`
                : `${total.toLocaleString()} matching incidents · click any row to inspect or change status`}
            </p>
          </div>
          <div className="detections-filter-row">
            <label className="filter-search">
              <Search size={14} aria-hidden="true" />
              <span className="sr-only">Filter detections by ID, source, or category</span>
              <Input
                type="search"
                value={searchInput}
                onChange={(event) => setSearchInput(event.target.value)}
                placeholder="Filter ID, IP, category…"
              />
            </label>
            <Select
              value={severity}
              onValueChange={(value) => setSeverity(value as Severity | "All")}
            >
              <SelectTrigger className="filter-select" aria-label="Filter by severity">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="All">All severities</SelectItem>
                <SelectItem value="Critical">Critical</SelectItem>
                <SelectItem value="High">High</SelectItem>
                <SelectItem value="Medium">Medium</SelectItem>
                <SelectItem value="Low">Low</SelectItem>
              </SelectContent>
            </Select>
            <Select
              value={status}
              onValueChange={(value) => setStatus(value as IncidentStatus | "All")}
            >
              <SelectTrigger className="filter-select" aria-label="Filter by status">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="All">All statuses</SelectItem>
                <SelectItem value="Open">Open</SelectItem>
                <SelectItem value="Contained">Contained</SelectItem>
              </SelectContent>
            </Select>
            {hasFilters ? (
              <Button
                variant="ghost"
                className="action-button"
                type="button"
                onClick={clearFilters}
              >
                <X size={14} aria-hidden="true" /> Clear
              </Button>
            ) : null}
            <Button
              variant="ghost"
              className="action-button"
              type="button"
              disabled={offline}
              onClick={onOpenAnalyze}
            >
              <FlaskConical size={14} aria-hidden="true" />
              <span>Analyze flow</span>
            </Button>
            <Button
              variant="ghost"
              className="export-button"
              type="button"
              disabled={exporting}
              onClick={() => void handleExportCsv()}
            >
              {exporting ? (
                <Loader2 size={14} className="spin" aria-hidden="true" />
              ) : (
                <FileDown size={14} aria-hidden="true" />
              )}
              <span>Export CSV</span>
            </Button>
          </div>
        </div>

        {selectedIds.length > 0 ? (
          <div className="bulk-action-bar" role="region" aria-label="Bulk incident actions">
            <span className="tabular-nums font-medium">
              {selectedIds.length} incident{selectedIds.length === 1 ? "" : "s"} selected
            </span>
            <div className="view-toolbar-actions">
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="action-button action-button-primary"
                disabled={offline || bulkBusy}
                onClick={() => void handleBulkStatus("Contained")}
              >
                {bulkBusy ? (
                  <Loader2 size={13} className="spin" aria-hidden="true" />
                ) : (
                  <CheckCircle2 size={13} aria-hidden="true" />
                )}
                <span>Mark Contained</span>
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="action-button"
                disabled={offline || bulkBusy}
                onClick={() => void handleBulkStatus("Open")}
              >
                <RotateCcw size={13} aria-hidden="true" />
                <span>Reopen</span>
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="action-button"
                disabled={bulkBusy}
                onClick={() => setSelectedIds([])}
              >
                <X size={13} aria-hidden="true" />
                <span>Clear</span>
              </Button>
            </div>
          </div>
        ) : null}

        {!offline && query.isLoading ? (
          <div className="table-skeleton" aria-label="Loading detections">
            {Array.from({ length: 6 }, (_, i) => (
              <span className="skeleton-line" key={i} />
            ))}
          </div>
        ) : rows.length === 0 ? (
          <div className="empty-table">
            <p>
              {hasFilters
                ? "No incidents match the active search or filters."
                : "No detections recorded yet. Run a simulation to score traffic."}
            </p>
            <div className="empty-table-actions">
              {hasFilters ? (
                <Button
                  variant="ghost"
                  className="action-button"
                  type="button"
                  onClick={clearFilters}
                >
                  Clear filters
                </Button>
              ) : !offline ? (
                <Button
                  variant="ghost"
                  className="action-button"
                  type="button"
                  disabled={simulation.isPending}
                  onClick={() => simulation.mutate(20)}
                >
                  <Play size={14} aria-hidden="true" /> Run simulation
                </Button>
              ) : null}
            </div>
          </div>
        ) : (
          <div
            className="table-scroll"
            role="region"
            aria-label="Detections table; scroll horizontally on narrow screens"
            tabIndex={0}
          >
            <table className="incident-table">
              <thead>
                <tr>
                  <th scope="col" className="w-10">
                    <Checkbox
                      aria-label="Select all incidents on this page"
                      checked={allPageSelected}
                      onCheckedChange={togglePageSelection}
                    />
                  </th>
                  {COLUMNS.map((col) => {
                    const active = sort === col.key;
                    const ariaSort = active
                      ? order === "asc"
                        ? "ascending"
                        : "descending"
                      : "none";
                    return (
                      <th
                        key={col.key}
                        scope="col"
                        aria-sort={ariaSort}
                        className={col.alignRight ? "text-right" : undefined}
                      >
                        <button
                          type="button"
                          className={`sort-header-btn${active ? " sort-header-active" : ""}${col.alignRight ? " sort-header-right" : ""}`}
                          onClick={() => toggleSort(col.key)}
                        >
                          <span>{col.label}</span>
                          {active ? (
                            order === "asc" ? (
                              <ArrowUp size={12} aria-hidden="true" />
                            ) : (
                              <ArrowDown size={12} aria-hidden="true" />
                            )
                          ) : (
                            <ArrowUpDown size={12} className="sort-idle-icon" aria-hidden="true" />
                          )}
                        </button>
                      </th>
                    );
                  })}
                  <th scope="col">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((incident) => {
                  const checked = selectedIds.includes(incident.id);
                  return (
                    <tr
                      key={incident.id}
                      className={`clickable-row${checked ? " selected-row" : ""}`}
                      onClick={() => onSelectIncident(incident)}
                    >
                      <td onClick={(event) => event.stopPropagation()}>
                        <Checkbox
                          aria-label={`Select incident ${incident.id}`}
                          checked={checked}
                          onCheckedChange={() => toggleRowSelection(incident.id)}
                        />
                      </td>
                      <td className="font-mono tabular-nums font-medium">{incident.id}</td>
                      <td>{incident.category}</td>
                      <td className="source-cell tabular-nums">{incident.source}</td>
                      <td>
                        <span
                          className={`severity-text severity-text-${incident.severity.toLowerCase()}`}
                        >
                          {incident.severity}
                        </span>
                      </td>
                      <td>
                        <span
                          className={`status-label status-label-${incident.status.toLowerCase()}`}
                        >
                          {incident.status}
                        </span>
                      </td>
                      <td className="text-right">
                        <span className="confidence-value tabular-nums">
                          {incident.confidence.toFixed(1)}%
                        </span>
                      </td>
                      <td className="text-right font-mono tabular-nums">
                        {incident.blockIndex !== null ? `#${incident.blockIndex}` : "—"}
                      </td>
                      <td
                        className="time-cell tabular-nums"
                        title={incident.detectedAt || undefined}
                      >
                        {incident.firstSeen}
                      </td>
                      <td onClick={(event) => event.stopPropagation()}>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="inspect-button"
                          type="button"
                          onClick={() => onSelectIncident(incident)}
                          aria-label={`Inspect ${incident.id}`}
                        >
                          <Eye size={14} aria-hidden="true" />
                          <span>Inspect</span>
                        </Button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        <div className="pagination-bar">
          <span className="tabular-nums">
            Showing {startItem}–{endItem} of {total.toLocaleString()} · Page {page} of {pageCount}
          </span>
          <div>
            <Button
              variant="ghost"
              size="sm"
              className="inspect-button"
              type="button"
              disabled={page <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
            >
              <ChevronLeft size={14} aria-hidden="true" /> Previous
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="inspect-button"
              type="button"
              disabled={page >= pageCount}
              onClick={() => setPage((p) => Math.min(pageCount, p + 1))}
            >
              Next <ChevronRight size={14} aria-hidden="true" />
            </Button>
          </div>
        </div>
      </section>
    </div>
  );
}
