import { useEffect, useRef, useState } from "react";
import { ChevronLeft, ChevronRight, Eye, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { Severity } from "@/lib/threat/types";
import type { IncidentRow } from "./incident-rows";

type IncidentTableProps = {
  rows: IncidentRow[];
  total: number;
  page: number;
  pageSize: number;
  loading: boolean;
  demo: boolean;
  severity: Severity | "All";
  hasSearch: boolean;
  onSeverityChange: (severity: Severity | "All") => void;
  onPageChange: (page: number) => void;
};

export function IncidentTable({
  rows,
  total,
  page,
  pageSize,
  loading,
  demo,
  severity,
  hasSearch,
  onSeverityChange,
  onPageChange,
}: IncidentTableProps) {
  const [selectedIncident, setSelectedIncident] = useState<IncidentRow | null>(null);
  const dialogRef = useRef<HTMLDialogElement>(null);
  const pageCount = Math.max(1, Math.ceil(total / pageSize));
  const filtered = severity !== "All" || hasSearch;

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (selectedIncident && !dialog.open) dialog.showModal();
    if (!selectedIncident && dialog.open) dialog.close();
  }, [selectedIncident]);

  return (
    <section className="panel incidents-panel" id="detections" aria-labelledby="incidents-title">
      <div className="panel-heading incidents-heading">
        <div>
          <div className="section-kicker">DETECTION QUEUE</div>
          <h2 id="incidents-title">Recent incidents</h2>
          <p>
            {demo
              ? "Offline demo events"
              : `${total.toLocaleString()} detections recorded on the ledger · newest first`}
          </p>
        </div>
        <div className="severity-select-wrap">
          <Select
            value={severity}
            onValueChange={(value) => onSeverityChange(value as Severity | "All")}
          >
            <SelectTrigger className="severity-select" aria-label="Filter by severity">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="All">All severities</SelectItem>
              <SelectItem value="Critical">Critical</SelectItem>
              <SelectItem value="High">High</SelectItem>
              <SelectItem value="Medium">Medium</SelectItem>
              <SelectItem value="Low">Low</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      {loading ? (
        <div className="table-skeleton" aria-label="Loading incidents">
          {Array.from({ length: 5 }, (_, i) => (
            <span className="skeleton-line" key={i} />
          ))}
        </div>
      ) : (
        <div
          className="table-scroll"
          role="region"
          aria-label="Recent incidents; scroll horizontally to see all columns"
          tabIndex={0}
        >
          <table className="incident-table">
            <thead>
              <tr>
                <th scope="col">Detection</th>
                <th scope="col">Source</th>
                <th scope="col">Severity</th>
                <th scope="col">Confidence</th>
                <th scope="col">First seen</th>
                <th scope="col">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((incident) => (
                <tr key={incident.id}>
                  <td>
                    <div className="incident-name-cell">
                      <span
                        className={`incident-severity-mark mark-${incident.severity.toLowerCase()}`}
                        aria-hidden="true"
                      />
                      <div>
                        <strong>{incident.title}</strong>
                        <span>
                          {incident.id} <span className="table-divider">/</span>{" "}
                          {incident.blockIndex
                            ? `Block #${incident.blockIndex}`
                            : incident.category}
                        </span>
                      </div>
                    </div>
                  </td>
                  <td className="source-cell">{incident.source}</td>
                  <td>
                    <span className={`severity-pill severity-${incident.severity.toLowerCase()}`}>
                      {incident.severity}
                    </span>
                  </td>
                  <td>
                    <span className="confidence-value">{incident.confidence.toFixed(1)}%</span>
                  </td>
                  <td className="time-cell" title={incident.detectedAt || undefined}>
                    {incident.firstSeen}
                  </td>
                  <td>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="inspect-button"
                      type="button"
                      onClick={() => setSelectedIncident(incident)}
                      aria-label={`Inspect ${incident.id}`}
                    >
                      <Eye size={14} aria-hidden="true" />
                      <span>Inspect</span>
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length === 0 ? (
            <div className="empty-table">
              {filtered
                ? "No incidents match these filters."
                : "No detections yet. Run a simulation to score test traffic."}
            </div>
          ) : null}
        </div>
      )}

      {!demo && total > pageSize ? (
        <div className="pagination-bar">
          <span>
            Page {page} of {pageCount}
          </span>
          <div>
            <Button
              variant="ghost"
              size="sm"
              className="inspect-button"
              type="button"
              disabled={page <= 1}
              onClick={() => onPageChange(page - 1)}
            >
              <ChevronLeft size={14} aria-hidden="true" /> Newer
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="inspect-button"
              type="button"
              disabled={page >= pageCount}
              onClick={() => onPageChange(page + 1)}
            >
              Older <ChevronRight size={14} aria-hidden="true" />
            </Button>
          </div>
        </div>
      ) : null}

      <dialog
        ref={dialogRef}
        className="incident-dialog"
        aria-labelledby="incident-dialog-title"
        onClose={() => setSelectedIncident(null)}
        onClick={(event) => {
          if (event.target === event.currentTarget) dialogRef.current?.close();
        }}
      >
        {selectedIncident ? (
          <div className="dialog-content">
            <div className="dialog-topline">
              <span className={`severity-pill severity-${selectedIncident.severity.toLowerCase()}`}>
                {selectedIncident.severity} priority
              </span>
              <Button
                variant="ghost"
                size="icon"
                className="dialog-close"
                type="button"
                onClick={() => dialogRef.current?.close()}
                aria-label="Close incident details"
              >
                <X size={18} aria-hidden="true" />
              </Button>
            </div>
            <div className="section-kicker">
              {selectedIncident.id} · {selectedIncident.category}
            </div>
            <h2 id="incident-dialog-title">{selectedIncident.title}</h2>
            <p className="dialog-description">{selectedIncident.description}</p>
            <div className="dialog-facts">
              <div>
                <span>Source</span>
                <strong>{selectedIncident.source}</strong>
              </div>
              <div>
                <span>Model confidence</span>
                <strong>{selectedIncident.confidence.toFixed(1)}%</strong>
              </div>
              <div>
                <span>Detected</span>
                <strong>
                  {selectedIncident.detectedAt
                    ? new Date(selectedIncident.detectedAt).toLocaleString()
                    : selectedIncident.firstSeen}
                </strong>
              </div>
              <div>
                <span>Status</span>
                <strong>{selectedIncident.status}</strong>
              </div>
              {selectedIncident.modelVersion ? (
                <div>
                  <span>Model version</span>
                  <strong>{selectedIncident.modelVersion}</strong>
                </div>
              ) : null}
              {selectedIncident.hash ? (
                <div>
                  <span>Block hash</span>
                  <strong>
                    {selectedIncident.hash.slice(0, 10)}…{selectedIncident.hash.slice(-6)}
                  </strong>
                </div>
              ) : null}
            </div>
            <p className="dialog-note">
              {demo
                ? "Offline demo event — the live API could not be reached."
                : "Stored on the tamper-evident ledger. Use Verify integrity to re-check every block hash."}
            </p>
          </div>
        ) : null}
      </dialog>
    </section>
  );
}
