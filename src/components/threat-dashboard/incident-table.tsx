"use client";

import { useEffect, useRef, useState } from "react";
import { Eye, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { filterIncidents, incidentData, type Incident, type Severity } from "./demo-data";

type IncidentTableProps = {
  searchTerm: string;
};

export function IncidentTable({ searchTerm }: IncidentTableProps) {
  const [severityFilter, setSeverityFilter] = useState<Severity | "All">("All");
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const dialogRef = useRef<HTMLDialogElement>(null);

  const filteredIncidents = filterIncidents(incidentData, searchTerm, severityFilter);

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
          <p>Illustrative events for the dashboard preview</p>
        </div>
        <div className="severity-select-wrap">
          <Select
            value={severityFilter}
            onValueChange={(value) => setSeverityFilter(value as Severity | "All")}
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

      <div className="table-scroll" role="region" aria-label="Recent sample incidents; scroll horizontally to see all columns" tabIndex={0}>
        <table className="incident-table">
          <thead>
            <tr>
              <th scope="col">Detection</th>
              <th scope="col">Source</th>
              <th scope="col">Severity</th>
              <th scope="col">Confidence</th>
              <th scope="col">First seen</th>
              <th scope="col"><span className="sr-only">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            {filteredIncidents.map((incident) => (
              <tr key={incident.id}>
                <td>
                  <div className="incident-name-cell">
                    <span className={`incident-severity-mark mark-${incident.severity.toLowerCase()}`} aria-hidden="true" />
                    <div>
                      <strong>{incident.title}</strong>
                      <span>{incident.id} <span className="table-divider">/</span> {incident.category}</span>
                    </div>
                  </div>
                </td>
                <td className="source-cell">{incident.source}</td>
                <td><span className={`severity-pill severity-${incident.severity.toLowerCase()}`}>{incident.severity}</span></td>
                <td><span className="confidence-value">{incident.confidence.toFixed(1)}%</span></td>
                <td className="time-cell">{incident.firstSeen}</td>
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
        {filteredIncidents.length === 0 ? (
          <div className="empty-table">No sample incidents match this search.</div>
        ) : null}
      </div>

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
              <Button variant="ghost" size="icon" className="dialog-close" type="button" onClick={() => dialogRef.current?.close()} aria-label="Close incident details">
                <X size={18} aria-hidden="true" />
              </Button>
            </div>
            <div className="section-kicker">{selectedIncident.id} · {selectedIncident.category}</div>
            <h2 id="incident-dialog-title">{selectedIncident.title}</h2>
            <p className="dialog-description">{selectedIncident.description}</p>
            <div className="dialog-facts">
              <div><span>Source</span><strong>{selectedIncident.source}</strong></div>
              <div><span>Model confidence</span><strong>{selectedIncident.confidence.toFixed(1)}%</strong></div>
              <div><span>First seen</span><strong>{selectedIncident.firstSeen}</strong></div>
              <div><span>Preview status</span><strong>{selectedIncident.status}</strong></div>
            </div>
            <p className="dialog-note">Sample preview only. This event is not connected to a live detector or response workflow.</p>
          </div>
        ) : null}
      </dialog>
    </section>
  );
}
