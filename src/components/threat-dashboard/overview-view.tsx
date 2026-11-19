import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Eye,
  Flame,
  FlaskConical,
  Loader2,
  Play,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { usePreferences } from "@/hooks/use-preferences";
import { useIntegrity, useSimulation } from "@/hooks/use-threat-data";
import { DEFAULT_FILTERS, incidentsQuery } from "@/lib/api";
import type { DashboardMetrics } from "@/lib/threat/types";
import type { IncidentRow } from "./incident-rows";
import { relativeTime, toIncidentRow } from "./incident-rows";
import { MetricCard } from "./metric-card";
import { TrafficChart } from "./traffic-chart";
import {
  incidentData as demoIncidents,
  severitySummary as demoSeverity,
  trafficSeries as demoTraffic,
} from "./demo-data";

const SIMULATION_SIZE = 20;

type OverviewViewProps = {
  metrics: DashboardMetrics | undefined;
  metricsLoading: boolean;
  metricsFetching: boolean;
  metricsError: unknown;
  offline: boolean;
  onRetry: () => void;
  onSelectIncident: (incident: IncidentRow) => void;
  onNavigateDetections: () => void;
  onNavigateAudit: () => void;
  onOpenAnalyze: () => void;
};

export function OverviewView({
  metrics,
  metricsLoading,
  metricsFetching,
  metricsError,
  offline,
  onRetry,
  onSelectIncident,
  onNavigateDetections,
  onNavigateAudit,
  onOpenAnalyze,
}: OverviewViewProps) {
  const { refetchInterval, refreshSeconds } = usePreferences();
  const simulation = useSimulation();
  const integrity = useIntegrity();

  const latestQuery = useQuery({
    ...incidentsQuery({ ...DEFAULT_FILTERS, page: 1, pageSize: 5 }, refetchInterval),
    enabled: !offline,
  });

  const verification = integrity.result;
  const errorMessage =
    metricsError instanceof Error ? metricsError.message : "The live API could not be reached.";

  const totalEvents = offline ? 8412 : (metrics?.eventsAnalyzed ?? 0);
  const attacksDetected = offline ? 68 : (metrics?.threatsDetected ?? 0);
  const criticalOpen = offline
    ? demoIncidents.filter((i) => i.severity === "Critical" && i.status === "Open").length
    : (metrics?.criticalOpen ?? 0);
  const severityRows = offline ? demoSeverity : (metrics?.severitySummary ?? []);
  const traffic = offline ? demoTraffic : (metrics?.traffic ?? []);
  const hasTraffic = traffic.some((point) => point.events > 0);

  const latestRows: IncidentRow[] = offline
    ? demoIncidents.slice(0, 5)
    : (latestQuery.data?.items ?? []).map(toIncidentRow);

  const chainStatusValue = verification
    ? verification.valid
      ? "Valid"
      : `Tampered #${verification.badIndex}`
    : offline
      ? "Offline"
      : `${(metrics?.chainLength ?? 0).toLocaleString()} blocks`;

  const chainStatusNote = verification
    ? verification.valid
      ? `All ${verification.length} blocks verified ${relativeTime(verification.checkedAt)}`
      : (verification.reason ?? "Tampering detected")
    : offline
      ? "Verification unavailable offline"
      : "Unverified this session · run Verify integrity";

  return (
    <div className="view-stack">
      <div className="view-toolbar">
        <div className="view-toolbar-meta">
          {offline ? (
            <span className="env-tag env-tag-demo">Demo data</span>
          ) : (
            <span className="env-tag env-tag-live">Live DB</span>
          )}
          <span aria-hidden="true">·</span>
          <span>
            {offline
              ? "Offline fallback active"
              : refreshSeconds === 0
                ? "Auto-refresh off"
                : `Refreshes every ${refreshSeconds}s`}
          </span>
          {metrics?.model.modelVersion ? (
            <>
              <span aria-hidden="true">·</span>
              <span className="font-mono">{metrics.model.modelVersion}</span>
            </>
          ) : null}
        </div>
        <div className="view-toolbar-actions">
          <Button
            variant="ghost"
            className="action-button action-button-primary"
            type="button"
            disabled={offline || simulation.isPending}
            onClick={() => simulation.mutate(SIMULATION_SIZE)}
          >
            {simulation.isPending ? (
              <Loader2 size={15} className="spin" aria-hidden="true" />
            ) : (
              <Play size={15} aria-hidden="true" />
            )}
            <span>{simulation.isPending ? "Simulating…" : "Run simulation"}</span>
          </Button>
          <Button
            variant="ghost"
            className="action-button"
            type="button"
            disabled={offline}
            onClick={onOpenAnalyze}
          >
            <FlaskConical size={15} aria-hidden="true" />
            <span>Analyze flow</span>
          </Button>
          <Button
            variant="ghost"
            className="action-button"
            type="button"
            disabled={offline || integrity.isPending}
            onClick={() => integrity.verify()}
          >
            {integrity.isPending ? (
              <Loader2 size={15} className="spin" aria-hidden="true" />
            ) : (
              <ShieldCheck size={15} aria-hidden="true" />
            )}
            <span>Verify integrity</span>
          </Button>
        </div>
      </div>

      {offline ? (
        <div className="status-banner status-banner-error" role="alert">
          <AlertTriangle size={16} aria-hidden="true" />
          <p>
            <strong>Live data unavailable.</strong>{" "}
            <span>{errorMessage} Showing labelled demo fallback until the connection returns.</span>
          </p>
          <Button variant="ghost" className="action-button" type="button" onClick={onRetry}>
            <RefreshCw size={14} aria-hidden="true" /> Retry
          </Button>
        </div>
      ) : verification && !verification.valid ? (
        <div className="status-banner status-banner-error" role="alert">
          <ShieldX size={16} aria-hidden="true" />
          <p>
            <strong>Ledger tampering detected at block #{verification.badIndex}.</strong>{" "}
            <span>{verification.reason} Inspect the audit ledger for details.</span>
          </p>
          <Button variant="ghost" className="action-button" type="button" onClick={onNavigateAudit}>
            Inspect ledger
          </Button>
        </div>
      ) : null}

      <section className="metrics-grid" aria-label="Security overview metrics">
        <MetricCard
          loading={metricsLoading}
          label="Total events"
          value={totalEvents.toLocaleString()}
          note={
            offline
              ? "Demo fallback value"
              : metricsFetching
                ? "Updating from ledger…"
                : "Traffic records scored by the model"
          }
          icon={Activity}
          accent="cyan"
        />
        <MetricCard
          loading={metricsLoading}
          label="Attacks detected"
          value={attacksDetected.toLocaleString()}
          note={
            offline
              ? "Demo fallback value"
              : metrics?.avgConfidence != null
                ? `Avg. confidence ${metrics.avgConfidence.toFixed(1)}%`
                : "No attacks recorded yet"
          }
          icon={ShieldAlert}
          accent="coral"
        />
        <MetricCard
          loading={metricsLoading}
          label="Critical open"
          value={criticalOpen.toLocaleString()}
          note={
            offline
              ? "Demo fallback value"
              : `${(metrics?.openIncidents ?? 0).toLocaleString()} total open incidents`
          }
          icon={Flame}
          accent="violet"
        />
        <MetricCard
          loading={metricsLoading}
          label="Chain status"
          value={chainStatusValue}
          note={chainStatusNote}
          icon={verification && !verification.valid ? ShieldX : ShieldCheck}
          accent={verification && !verification.valid ? "coral" : "green"}
        />
      </section>

      <section className="primary-grid" aria-label="Traffic activity and severity mix">
        <article className="panel traffic-panel">
          <div className="panel-heading">
            <div>
              <h2>Traffic &amp; threat signals</h2>
              <p>
                Events analyzed and detections in 2-hour buckets{offline ? " · demo fallback" : ""}
              </p>
            </div>
            <div className="chart-legend" aria-label="Chart legend">
              <span>
                <i className="legend-dot legend-events" />
                Events
              </span>
              <span>
                <i className="legend-dot legend-threats" />
                Attacks
              </span>
            </div>
          </div>
          {metricsLoading ? (
            <span className="skeleton-line chart-skeleton" aria-label="Loading traffic chart" />
          ) : hasTraffic ? (
            <TrafficChart data={traffic} />
          ) : (
            <div className="empty-chart">
              <p>No traffic in the last 24 hours. Run a simulation to score traffic records.</p>
              {!offline ? (
                <Button
                  variant="ghost"
                  className="action-button mt-3"
                  type="button"
                  disabled={simulation.isPending}
                  onClick={() => simulation.mutate(SIMULATION_SIZE)}
                >
                  <Play size={14} aria-hidden="true" /> Run simulation
                </Button>
              ) : null}
            </div>
          )}
          <div className="chart-footnote">
            <span>Last 24 hours</span>
            <span>UTC</span>
          </div>
        </article>

        <article className="panel severity-panel">
          <div className="panel-heading">
            <div>
              <h2>Severity summary</h2>
              <p>
                {attacksDetected.toLocaleString()} total detections{offline ? " · demo" : ""}
              </p>
            </div>
            <span className="panel-icon">
              <ShieldAlert size={16} aria-hidden="true" />
            </span>
          </div>
          <div className="severity-total">
            <strong className="tabular-nums">
              {metricsLoading ? "…" : attacksDetected.toLocaleString()}
            </strong>
            <span>recorded attacks</span>
          </div>
          <div className="severity-bars" aria-label="Detections by severity">
            {severityRows.map((item) => (
              <div className="severity-row" key={item.label}>
                <div className="severity-row-heading">
                  <span>
                    <i className={`severity-dot dot-${item.label.toLowerCase()}`} />
                    {item.label}
                  </span>
                  <strong className="tabular-nums">
                    {item.count.toLocaleString()} ({item.percent}%)
                  </strong>
                </div>
                <div className="severity-track">
                  <span
                    className={`severity-fill fill-${item.label.toLowerCase()}`}
                    style={{ width: `${item.percent}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
          <a
            className="text-link"
            href="#detections"
            onClick={(event) => {
              event.preventDefault();
              onNavigateDetections();
            }}
          >
            View all detections <ArrowUpRight size={14} aria-hidden="true" />
          </a>
        </article>
      </section>

      <section className="panel incidents-panel" aria-labelledby="overview-latest-title">
        <div className="panel-heading incidents-heading">
          <div>
            <h2 id="overview-latest-title">Latest incidents</h2>
            <p>
              {offline
                ? "5 latest offline demo detections"
                : "5 most recent attacks written to the audit ledger"}
            </p>
          </div>
          <a
            className="text-link text-link-inline"
            href="#detections"
            onClick={(event) => {
              event.preventDefault();
              onNavigateDetections();
            }}
          >
            View all <ArrowUpRight size={14} aria-hidden="true" />
          </a>
        </div>

        {latestQuery.isError && !offline ? (
          <div className="inline-error-box" role="alert">
            <span>Could not load latest incidents.</span>
            <Button
              variant="ghost"
              size="sm"
              type="button"
              onClick={() => void latestQuery.refetch()}
            >
              <RefreshCw size={13} aria-hidden="true" /> Retry
            </Button>
          </div>
        ) : !offline && latestQuery.isLoading ? (
          <div className="table-skeleton" aria-label="Loading latest incidents">
            {Array.from({ length: 5 }, (_, i) => (
              <span className="skeleton-line" key={i} />
            ))}
          </div>
        ) : latestRows.length === 0 ? (
          <div className="empty-table">
            No detections yet. Run a simulation to score traffic and record detections.
          </div>
        ) : (
          <div className="table-scroll" role="region" aria-label="Latest 5 incidents" tabIndex={0}>
            <table className="incident-table">
              <thead>
                <tr>
                  <th scope="col">Incident</th>
                  <th scope="col">Source</th>
                  <th scope="col">Severity</th>
                  <th scope="col">Status</th>
                  <th scope="col" className="text-right">
                    Confidence
                  </th>
                  <th scope="col">Detected</th>
                  <th scope="col">
                    <span className="sr-only">Inspect</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {latestRows.map((incident) => (
                  <tr
                    key={incident.id}
                    className="clickable-row"
                    onClick={() => onSelectIncident(incident)}
                  >
                    <td>
                      <div className="incident-name-cell">
                        <div>
                          <strong>{incident.category}</strong>
                          <span className="font-mono tabular-nums">
                            {incident.id}
                            {incident.blockIndex !== null ? ` · Block #${incident.blockIndex}` : ""}
                          </span>
                        </div>
                      </div>
                    </td>
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
                    <td className="time-cell tabular-nums" title={incident.detectedAt || undefined}>
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
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
