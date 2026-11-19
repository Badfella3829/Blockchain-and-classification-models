import { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Boxes,
  BrainCircuit,
  Check,
  ChevronRight,
  CircleHelp,
  FileDown,
  Gauge,
  LayoutDashboard,
  Loader2,
  Play,
  Radar,
  RefreshCw,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useIntegrityCheck, useSimulation, useThreatData } from "@/hooks/use-threat-data";
import { DEFAULT_FILTERS, fetchAllIncidents } from "@/lib/api";
import type { LedgerBlock, Severity } from "@/lib/threat/types";
import { IncidentTable } from "./incident-table";
import { downloadIncidents, relativeTime, toIncidentRow } from "./incident-rows";
import { MetricCard } from "./metric-card";
import { TrafficChart } from "./traffic-chart";
import { auditPreview, filterIncidents, incidentData, severitySummary as demoSeverity, trafficSeries as demoTraffic } from "./demo-data";

const PAGE_SIZE = 8;
const SIMULATION_SIZE = 20;

const navigation = [
  { label: "Overview", href: "#overview", icon: LayoutDashboard },
  { label: "Detections", href: "#detections", icon: Radar },
  { label: "Audit ledger", href: "#audit", icon: Boxes },
  { label: "Model health", href: "#model-health", icon: BrainCircuit },
];

function Brand() {
  return (
    <a className="brand-lockup" href="#overview" aria-label="Sentinel overview">
      <span className="brand-mark" aria-hidden="true"><Shield size={18} strokeWidth={2.2} /></span>
      <span className="brand-copy"><strong>SENTINEL</strong><small>THREAT INTELLIGENCE</small></span>
    </a>
  );
}

function NavigationLinks({ mobile = false }: { mobile?: boolean }) {
  return (
    <nav className={mobile ? "mobile-nav" : "side-nav"} aria-label={mobile ? "Mobile navigation" : "Main navigation"}>
      {navigation.map(({ label, href, icon: Icon }, index) => (
        <a className={`nav-link${index === 0 ? " nav-link-active" : ""}`} href={href} key={label}>
          <Icon size={17} strokeWidth={1.8} aria-hidden="true" />
          <span>{label}</span>
          {index === 0 ? <span className="nav-active-mark" aria-hidden="true" /> : null}
        </a>
      ))}
    </nav>
  );
}

function useDebounced<T>(value: T, delay = 300) {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const id = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(id);
  }, [value, delay]);
  return debounced;
}

function describeBlock(block: LedgerBlock) {
  if (typeof block.event === "string") return block.event;
  const event = block.event as { category?: string; severity?: string };
  return `${event.severity ?? ""} ${event.category ?? "Detection"} recorded`.trim();
}

const shortHash = (hash: string) => `${hash.slice(0, 4)}…${hash.slice(-4)}`;

export function DashboardShell() {
  const [searchTerm, setSearchTerm] = useState("");
  const [severity, setSeverity] = useState<Severity | "All">("All");
  const [page, setPage] = useState(1);
  const [exporting, setExporting] = useState(false);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const debouncedSearch = useDebounced(searchTerm);
  const safeSearch = debouncedSearch.replace(/[^\w .:-]/g, "").slice(0, 60);

  const filters = useMemo(() => ({ severity, search: safeSearch, page, pageSize: PAGE_SIZE }), [severity, safeSearch, page]);
  const { metrics, incidents, blocks, offline } = useThreatData(filters);
  const simulation = useSimulation();
  const integrity = useIntegrityCheck();

  useEffect(() => setPage(1), [severity, safeSearch]);

  useEffect(() => {
    const focusSearch = (event: KeyboardEvent) => {
      const target = event.target;
      if (
        event.key === "/" &&
        !(target instanceof HTMLElement && (target.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName)))
      ) {
        event.preventDefault();
        searchInputRef.current?.focus();
      }
    };
    window.addEventListener("keydown", focusSearch);
    return () => window.removeEventListener("keydown", focusSearch);
  }, []);

  const live = metrics.data;
  const loading = !live && !offline;
  const demoRows = filterIncidents(incidentData, searchTerm, severity);
  const rows = offline ? demoRows : (incidents.data?.items ?? []).map(toIncidentRow);
  const total = offline ? demoRows.length : (incidents.data?.total ?? 0);
  const severityRows = offline ? demoSeverity : (live?.severitySummary ?? []);
  const threatTotal = offline ? 68 : (live?.threatsDetected ?? 0);
  const traffic = offline ? demoTraffic : (live?.traffic ?? []);
  const hasTraffic = traffic.some((point) => point.events > 0);
  const verification = integrity.result;
  const errorMessage = metrics.error instanceof Error ? metrics.error.message : "The live API could not be reached.";

  async function exportCsv() {
    if (offline) {
      downloadIncidents(demoRows, "sentinel-demo-incidents.csv");
      return;
    }
    setExporting(true);
    try {
      const all = await fetchAllIncidents({ ...DEFAULT_FILTERS, severity, search: safeSearch });
      if (all.length === 0) {
        toast.info("Nothing to export", { description: "No incidents match the current filters." });
        return;
      }
      downloadIncidents(all.map(toIncidentRow));
      toast.success(`Exported ${all.length} incidents`);
    } catch (error) {
      toast.error("Export failed", { description: error instanceof Error ? error.message : String(error) });
    } finally {
      setExporting(false);
    }
  }

  const integrityValue = verification ? (verification.valid ? "Valid" : `Block #${verification.badIndex}`) : offline ? "Offline" : "Unchecked";
  const integrityNote = verification
    ? verification.valid
      ? `${verification.length} blocks verified ${relativeTime(verification.checkedAt)}`
      : verification.reason ?? "Tampering detected"
    : `${live?.chainLength ?? 0} blocks · run Verify integrity`;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <Brand />
        <div className="sidebar-label">WORKSPACE</div>
        <NavigationLinks />
        <div className="sidebar-spacer" />
        <div className="sidebar-support">
          <span className="support-icon"><CircleHelp size={16} aria-hidden="true" /></span>
          <span><strong>Need data?</strong><small>Run a simulation</small></span>
          <ChevronRight size={15} aria-hidden="true" />
        </div>
        <div className="sidebar-footer">
          <span className="avatar-mark">S</span>
          <span className="account-copy"><strong>Security team</strong><small>{offline ? "Offline demo" : "Live workspace"}</small></span>
          <Settings size={16} aria-hidden="true" />
        </div>
      </aside>

      <div className="mobile-header">
        <Brand />
        {offline ? <span className="preview-badge">DEMO DATA</span> : <span className="live-badge"><span className="status-dot" />LIVE</span>}
      </div>
      <NavigationLinks mobile />

      <main className="dashboard-main" id="overview">
        <header className="page-header">
          <div className="page-heading-copy">
            <div className="breadcrumb"><span>SECURITY OPERATIONS</span><span className="breadcrumb-slash">/</span><span>OVERVIEW</span></div>
            <div className="title-line">
              <h1>Threat overview</h1>
              {offline ? <span className="preview-badge">DEMO DATA</span> : <span className="live-badge"><span className="status-dot" />LIVE</span>}
              {live ? <span className="model-version-chip" title="Model version">{live.model.modelVersion}</span> : null}
            </div>
            <p>Monitor detection signals, model health, and audit activity.</p>
          </div>
          <div className="header-actions">
            <label className="search-box">
              <Search size={16} aria-hidden="true" />
              <span className="sr-only">Search incidents</span>
              <Input
                ref={searchInputRef}
                type="search"
                aria-keyshortcuts="/"
                onKeyDown={(event) => {
                  if (event.key === "/") event.preventDefault();
                }}
                value={searchTerm}
                onChange={(event) => setSearchTerm(event.target.value)}
                placeholder="Search ID, source, category"
              />
              <kbd>/</kbd>
            </label>
            <Button
              variant="ghost"
              className="action-button"
              type="button"
              disabled={offline || simulation.isPending}
              onClick={() => simulation.mutate(SIMULATION_SIZE)}
            >
              {simulation.isPending ? <Loader2 size={15} className="spin" aria-hidden="true" /> : <Play size={15} aria-hidden="true" />}
              <span>{simulation.isPending ? "Simulating…" : "Run simulation"}</span>
            </Button>
            <Button
              variant="ghost"
              className="action-button"
              type="button"
              disabled={offline || integrity.isPending}
              onClick={() => integrity.mutate()}
            >
              {integrity.isPending ? <Loader2 size={15} className="spin" aria-hidden="true" /> : <ShieldCheck size={15} aria-hidden="true" />}
              <span>Verify integrity</span>
            </Button>
            <Button variant="ghost" className="export-button" type="button" disabled={exporting} onClick={exportCsv}>
              {exporting ? <Loader2 size={15} className="spin" aria-hidden="true" /> : <FileDown size={15} aria-hidden="true" />}
              <span>Export CSV</span>
            </Button>
          </div>
        </header>

        {offline ? (
          <div className="preview-notice error-banner" role="alert">
            <span className="notice-icon"><AlertTriangle size={16} aria-hidden="true" /></span>
            <p><strong>Live data unavailable</strong><span>{errorMessage} Showing offline demo data until the connection returns.</span></p>
            <Button variant="ghost" className="action-button" type="button" onClick={() => void metrics.refetch()}>
              <RefreshCw size={14} aria-hidden="true" /> Retry
            </Button>
          </div>
        ) : verification && !verification.valid ? (
          <div className="preview-notice error-banner" role="alert">
            <span className="notice-icon"><ShieldX size={16} aria-hidden="true" /></span>
            <p><strong>Ledger tampering detected at block #{verification.badIndex}</strong><span>{verification.reason} Blocks from #{verification.badIndex} onward can no longer be trusted.</span></p>
          </div>
        ) : (
          <div className="preview-notice live-notice" role="status">
            <span className="notice-icon"><Activity size={16} aria-hidden="true" /></span>
            <p>
              <strong>Live ledger</strong>
              <span>
                {loading
                  ? "Connecting to the detection service…"
                  : `Scores come from the trained Random Forest; every detected attack is written to the hash-linked ledger. Refreshes every 5 seconds.`}
              </span>
            </p>
            <span className="notice-status"><span className="status-dot" /> {metrics.isFetching ? "Updating" : "Up to date"}</span>
          </div>
        )}

        <section className="metrics-grid" aria-label="Security metrics">
          <MetricCard loading={loading} label="Events analyzed" value={offline ? "8,412" : (live?.eventsAnalyzed ?? 0).toLocaleString()} note={offline ? "Demo value" : "Traffic records scored by the model"} icon={Activity} accent="cyan" />
          <MetricCard loading={loading} label="Threat signals" value={threatTotal.toLocaleString()} note={offline ? "Demo value" : "Attacks recorded on the ledger"} icon={ShieldAlert} accent="coral" />
          <MetricCard loading={loading} label="Avg. confidence" value={offline ? "94.6%" : live?.avgConfidence != null ? `${live.avgConfidence.toFixed(1)}%` : "—"} note={offline ? "Demo value" : "Mean attack probability of detections"} icon={Gauge} accent="violet" />
          <MetricCard loading={loading} label="Ledger integrity" value={integrityValue} note={offline ? "Not available offline" : integrityNote} icon={verification && !verification.valid ? ShieldX : ShieldCheck} accent={verification && !verification.valid ? "coral" : "green"} />
        </section>

        <section className="primary-grid" aria-label="Traffic and severity overview">
          <article className="panel traffic-panel">
            <div className="panel-heading">
              <div>
                <div className="section-kicker">ACTIVITY STREAM</div>
                <h2>Traffic &amp; threat signals</h2>
                <p>Events analyzed and detections per 2 hours{offline ? " · demo data" : ""}</p>
              </div>
              <div className="chart-legend" aria-label="Chart legend">
                <span><i className="legend-dot legend-events" />Events</span>
                <span><i className="legend-dot legend-threats" />Threat signals</span>
              </div>
            </div>
            {loading ? (
              <span className="skeleton-line chart-skeleton" aria-label="Loading chart" />
            ) : hasTraffic ? (
              <TrafficChart data={traffic} />
            ) : (
              <div className="empty-chart">No traffic in the last 24 hours. Run a simulation to send test records through the model.</div>
            )}
            <div className="chart-footnote"><span><Activity size={13} aria-hidden="true" /> Last 24 hours</span><span>UTC</span></div>
          </article>

          <article className="panel severity-panel">
            <div className="panel-heading">
              <div>
                <div className="section-kicker">SIGNAL BREAKDOWN</div>
                <h2>Severity mix</h2>
                <p>{threatTotal.toLocaleString()} detections{offline ? " · demo" : ""}</p>
              </div>
              <span className="panel-icon"><ShieldAlert size={17} aria-hidden="true" /></span>
            </div>
            <div className="severity-total"><strong>{loading ? "…" : threatTotal.toLocaleString()}</strong><span>signals detected</span></div>
            <div className="severity-bars" aria-label="Detections by severity">
              {severityRows.map((item) => (
                <div className="severity-row" key={item.label}>
                  <div className="severity-row-heading"><span><i className={`severity-dot dot-${item.label.toLowerCase()}`} />{item.label}</span><strong>{item.count}</strong></div>
                  <div className="severity-track"><span className={`severity-fill fill-${item.label.toLowerCase()}`} style={{ width: `${item.percent}%` }} /></div>
                </div>
              ))}
            </div>
            <a className="text-link" href="#detections">Review detections <ArrowUpRight size={14} aria-hidden="true" /></a>
          </article>
        </section>

        <section className="lower-grid" aria-label="Incidents and audit trail">
          <IncidentTable
            rows={rows}
            total={total}
            page={page}
            pageSize={offline ? Math.max(rows.length, 1) : PAGE_SIZE}
            loading={!offline && !incidents.data}
            demo={offline}
            severity={severity}
            hasSearch={Boolean(safeSearch)}
            onSeverityChange={setSeverity}
            onPageChange={setPage}
          />
          <aside className="panel audit-panel" id="audit" aria-labelledby="audit-title">
            <div className="panel-heading">
              <div>
                <div className="section-kicker">CHAIN ACTIVITY</div>
                <h2 id="audit-title">Audit ledger</h2>
                <p>{offline ? "Demo records" : `${live?.chainLength ?? 0} blocks · newest first`}</p>
              </div>
              {verification ? (
                <span className={`verified-chip${verification.valid ? "" : " tamper-chip"}`}>
                  {verification.valid ? <Check size={12} aria-hidden="true" /> : <ShieldX size={12} aria-hidden="true" />}
                  {verification.valid ? "Verified" : `Tampered #${verification.badIndex}`}
                </span>
              ) : null}
            </div>
            <div className="ledger-list">
              {offline
                ? auditPreview.map((entry, index) => (
                    <div className="ledger-entry" key={entry.id}>
                      <span className={`ledger-icon${index === 0 ? " ledger-icon-current" : ""}`}><Check size={13} aria-hidden="true" /></span>
                      <div className="ledger-copy"><strong>{entry.event}</strong><span>{entry.id} <i>·</i> {entry.time}</span></div>
                      <code>{entry.hash}</code>
                    </div>
                  ))
                : !blocks.data
                  ? Array.from({ length: 3 }, (_, i) => <span className="skeleton-line" style={{ height: 34, marginBottom: 10 }} key={i} />)
                  : blocks.data.map((block, index) => {
                      const tampered = verification && !verification.valid && verification.badIndex !== null && block.index >= verification.badIndex;
                      return (
                        <div className="ledger-entry" key={block.index}>
                          <span className={`ledger-icon${index === 0 ? " ledger-icon-current" : ""}`}>
                            {tampered ? <ShieldX size={13} aria-hidden="true" /> : <Check size={13} aria-hidden="true" />}
                          </span>
                          <div className="ledger-copy">
                            <strong>{describeBlock(block)}</strong>
                            <span>BLK-{String(block.index).padStart(5, "0")} <i>·</i> {relativeTime(block.timestamp)}</span>
                          </div>
                          <code title={block.hash}>{shortHash(block.hash)}</code>
                        </div>
                      );
                    })}
            </div>
            <div className="ledger-footnote">
              <ShieldCheck size={14} aria-hidden="true" />
              <span>Each block stores the SHA-256 hash of the previous one, so editing any record breaks every link after it.</span>
            </div>
          </aside>
        </section>

        <section className="panel model-panel" id="model-health" aria-labelledby="model-health-title">
          <div className="model-symbol"><BrainCircuit size={19} aria-hidden="true" /></div>
          <div className="model-copy">
            <div className="section-kicker">MODEL HEALTH</div>
            {live ? (
              <>
                <h2 id="model-health-title">{live.model.selectedModel} · {live.model.modelVersion}</h2>
                <p>Evaluated on the {live.model.evaluation} · {live.model.features.length} traffic features (labels excluded).</p>
                {live.model.scores ? (
                  <div className="model-scores">
                    <span>Accuracy <strong>{(live.model.scores.accuracy * 100).toFixed(1)}%</strong></span>
                    <span>Precision <strong>{(live.model.scores.precision * 100).toFixed(1)}%</strong></span>
                    <span>Recall <strong>{(live.model.scores.recall * 100).toFixed(1)}%</strong></span>
                    <span>F1 <strong>{(live.model.scores.f1 * 100).toFixed(1)}%</strong></span>
                  </div>
                ) : null}
              </>
            ) : (
              <>
                <h2 id="model-health-title">{offline ? "Model service offline" : "Loading model details…"}</h2>
                <p>{offline ? "Scores will appear once the live API is reachable." : "Reading the trained model's evaluation results."}</p>
              </>
            )}
          </div>
          <div className="model-state"><span className="state-dot" />{live ? "Model connected" : offline ? "Offline" : "Connecting"}</div>
        </section>

        <footer className="dashboard-footer">
          <span><Shield size={13} aria-hidden="true" /> Sentinel security workspace</span>
          <span>{offline ? "Offline demo data" : "Synthetic UNSW-NB15-style test traffic"}</span>
        </footer>
      </main>
    </div>
  );
}
