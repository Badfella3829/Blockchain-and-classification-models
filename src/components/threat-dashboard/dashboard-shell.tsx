"use client";

import { useEffect, useRef, useState } from "react";
import {
  Activity,
  ArrowUpRight,
  Bell,
  Boxes,
  BrainCircuit,
  Check,
  ChevronRight,
  CircleHelp,
  FileDown,
  Gauge,
  LayoutDashboard,
  Radar,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { IncidentTable } from "./incident-table";
import { MetricCard } from "./metric-card";
import { TrafficChart } from "./traffic-chart";
import { auditPreview, downloadIncidents, incidentData, severitySummary } from "./demo-data";

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

export function DashboardShell() {
  const [searchTerm, setSearchTerm] = useState("");
  const searchInputRef = useRef<HTMLInputElement>(null);

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

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <Brand />
        <div className="sidebar-label">WORKSPACE</div>
        <NavigationLinks />
        <div className="sidebar-spacer" />
        <div className="sidebar-support">
          <span className="support-icon"><CircleHelp size={16} aria-hidden="true" /></span>
          <span><strong>Need a hand?</strong><small>Explore the preview</small></span>
          <ChevronRight size={15} aria-hidden="true" />
        </div>
        <div className="sidebar-footer">
          <span className="avatar-mark">S</span>
          <span className="account-copy"><strong>Security team</strong><small>Preview workspace</small></span>
          <Settings size={16} aria-hidden="true" />
        </div>
      </aside>

      <div className="mobile-header"><Brand /><span className="preview-badge">PREVIEW</span></div>
      <NavigationLinks mobile />

      <main className="dashboard-main" id="overview">
        <header className="page-header">
          <div className="page-heading-copy">
            <div className="breadcrumb"><span>SECURITY OPERATIONS</span><span className="breadcrumb-slash">/</span><span>OVERVIEW</span></div>
            <div className="title-line"><h1>Threat overview</h1><span className="preview-badge">DEMO DATA</span></div>
            <p>Monitor detection signals, model health, and audit activity.</p>
          </div>
          <div className="header-actions">
            <label className="search-box">
              <Search size={16} aria-hidden="true" />
              <span className="sr-only">Search sample incidents</span>
          <Input
                ref={searchInputRef}
                type="search"
                aria-keyshortcuts="/"
                onKeyDown={(event) => {
                  if (event.key === "/") event.preventDefault();
                }}
                value={searchTerm}
                onChange={(event) => setSearchTerm(event.target.value)}
                placeholder="Search detections"
              />
              <kbd>/</kbd>
            </label>
            <Button variant="ghost" className="icon-button notification-button" type="button" aria-label="Notifications, demo preview">
              <Bell size={17} aria-hidden="true" />
              <span className="notification-dot" aria-hidden="true" />
            </Button>
            <Button variant="ghost" className="export-button" type="button" onClick={() => downloadIncidents(incidentData)}>
              <FileDown size={15} aria-hidden="true" />
              <span>Export CSV</span>
            </Button>
          </div>
        </header>

        <div className="preview-notice" role="note">
          <span className="notice-icon"><Sparkles size={16} aria-hidden="true" /></span>
          <p><strong>Preview workspace</strong><span>All events and metrics below are illustrative sample data. No trained model or live data source is connected.</span></p>
          <span className="notice-status"><span className="status-dot" /> Preview mode</span>
        </div>

        <section className="metrics-grid" aria-label="Sample security metrics">
          <MetricCard label="Events analyzed" value="8,412" note="Sample events in the last 24 hours" trend="12.4%" trendTone="positive" icon={Activity} accent="cyan" />
          <MetricCard label="Threat signals" value="68" note="Across 4 sample severity levels" trend="8.2%" trendTone="negative" icon={ShieldAlert} accent="coral" />
          <MetricCard label="Avg. confidence" value="94.6%" note="Illustrative model output" trend="2.1%" trendTone="positive" icon={Gauge} accent="violet" />
          <MetricCard label="Ledger integrity" value="Sample" note="Chain preview only" icon={ShieldCheck} accent="green" />
        </section>

        <section className="primary-grid" aria-label="Traffic and severity overview">
          <article className="panel traffic-panel">
            <div className="panel-heading">
              <div>
                <div className="section-kicker">ACTIVITY STREAM</div>
                <h2>Traffic &amp; threat signals</h2>
                <p>Events analyzed and detections by hour · sample data</p>
              </div>
              <div className="chart-legend" aria-label="Chart legend">
                <span><i className="legend-dot legend-events" />Events</span>
                <span><i className="legend-dot legend-threats" />Threat signals</span>
              </div>
            </div>
            <TrafficChart />
            <div className="chart-footnote"><span><Activity size={13} aria-hidden="true" /> Activity curve is illustrative</span><span>00:00 — 24:00 UTC</span></div>
          </article>

          <article className="panel severity-panel">
            <div className="panel-heading">
              <div>
                <div className="section-kicker">SIGNAL BREAKDOWN</div>
                <h2>Severity mix</h2>
                <p>68 sample detections</p>
              </div>
              <span className="panel-icon"><ShieldAlert size={17} aria-hidden="true" /></span>
            </div>
            <div className="severity-total"><strong>68</strong><span>signals detected</span></div>
            <div className="severity-bars" aria-label="Sample detections by severity">
              {severitySummary.map((item) => (
                <div className="severity-row" key={item.label}>
                  <div className="severity-row-heading"><span><i className={`severity-dot dot-${item.color}`} />{item.label}</span><strong>{item.count}</strong></div>
                  <div className="severity-track"><span className={`severity-fill fill-${item.color}`} style={{ width: `${item.percent}%` }} /></div>
                </div>
              ))}
            </div>
            <a className="text-link" href="#detections">Review detections <ArrowUpRight size={14} aria-hidden="true" /></a>
          </article>
        </section>

        <section className="lower-grid" aria-label="Incidents and audit trail">
          <IncidentTable searchTerm={searchTerm} />
          <aside className="panel audit-panel" id="audit" aria-labelledby="audit-title">
            <div className="panel-heading">
              <div>
                <div className="section-kicker">CHAIN ACTIVITY</div>
                <h2 id="audit-title">Audit ledger</h2>
                <p>Recent sample records</p>
              </div>
              <span className="verified-chip"><Check size={12} aria-hidden="true" /> Sample</span>
            </div>
            <div className="ledger-list">
              {auditPreview.map((entry, index) => (
                <div className="ledger-entry" key={entry.id}>
                  <span className={`ledger-icon${index === 0 ? " ledger-icon-current" : ""}`}><Check size={13} aria-hidden="true" /></span>
                  <div className="ledger-copy"><strong>{entry.event}</strong><span>{entry.id} <i>·</i> {entry.time}</span></div>
                  <code>{entry.hash}</code>
                </div>
              ))}
            </div>
            <div className="ledger-footnote"><ShieldCheck size={14} aria-hidden="true" /><span>Sample ledger only — not a live chain verification</span></div>
          </aside>
        </section>

        <section className="panel model-panel" id="model-health" aria-labelledby="model-health-title">
          <div className="model-symbol"><BrainCircuit size={19} aria-hidden="true" /></div>
          <div className="model-copy">
            <div className="section-kicker">MODEL HEALTH</div>
            <h2 id="model-health-title">Connect the trained model to enable live scoring</h2>
            <p>The dashboard is ready for a model service, but this preview has no model artifact or dataset connected.</p>
          </div>
          <div className="model-state"><span className="state-dot" />No model connected</div>
          <a className="model-link" href="#overview" aria-label="Back to overview">Preview UI <ArrowUpRight size={15} aria-hidden="true" /></a>
        </section>

        <footer className="dashboard-footer"><span><Shield size={13} aria-hidden="true" /> Sentinel security workspace</span><span>Interface preview · sample data only</span></footer>
      </main>
    </div>
  );
}
