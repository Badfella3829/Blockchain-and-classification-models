import { useEffect, useState } from "react";
import {
  Boxes,
  BrainCircuit,
  ChevronRight,
  CircleHelp,
  LayoutDashboard,
  Menu,
  PanelLeftClose,
  PanelLeftOpen,
  Radar,
  Shield,
} from "lucide-react";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Toaster } from "@/components/ui/sonner";
import { useHashView, type View } from "@/hooks/use-hash-view";
import { PreferencesProvider, usePreferences } from "@/hooks/use-preferences";
import { IntegrityProvider, useLiveMetrics } from "@/hooks/use-threat-data";
import { AnalyzeFlowDialog } from "./analyze-flow-dialog";
import { AuditView } from "./audit-view";
import { DetectionsView } from "./detections-view";
import { IncidentDrawer } from "./incident-drawer";
import type { IncidentRow } from "./incident-rows";
import { ModelHealthView } from "./model-health-view";
import { OverviewView } from "./overview-view";
import { HelpDialog, SettingsDialog, WorkspaceFooter } from "./shell-dialogs";
import { TopBarWidgets } from "./top-bar-widgets";

const NAVIGATION: {
  view: View;
  label: string;
  href: string;
  icon: typeof LayoutDashboard;
}[] = [
  { view: "overview", label: "Overview", href: "#overview", icon: LayoutDashboard },
  { view: "detections", label: "Detections", href: "#detections", icon: Radar },
  { view: "audit", label: "Audit ledger", href: "#audit", icon: Boxes },
  { view: "model-health", label: "Model health", href: "#model-health", icon: BrainCircuit },
];

const VIEW_META: Record<
  View,
  {
    crumb: string;
    title: string;
    subtitle: string;
  }
> = {
  overview: {
    crumb: "OVERVIEW",
    title: "Threat overview",
    subtitle: "Monitor live detection signals, severity distribution, and audit ledger integrity.",
  },
  detections: {
    crumb: "DETECTIONS",
    title: "Threat detections",
    subtitle:
      "Search, filter, sort, inspect block proofs, and record append-only containment updates.",
  },
  audit: {
    crumb: "AUDIT LEDGER",
    title: "Tamper-evident audit ledger",
    subtitle:
      "Inspect hash-linked SHA-256 blocks, verify chain integrity, and export the full ledger.",
  },
  "model-health": {
    crumb: "MODEL HEALTH",
    title: "Model health & drift",
    subtitle:
      "Review classifier metrics, confusion matrix, feature importances, and live attack-rate drift.",
  },
};

function Brand({
  collapsed = false,
  onNavigate,
}: {
  collapsed?: boolean;
  onNavigate: (view: View) => void;
}) {
  return (
    <a
      className="brand-lockup"
      href="#overview"
      aria-label="Sentinel Threat Intelligence overview"
      onClick={(event) => {
        event.preventDefault();
        onNavigate("overview");
      }}
    >
      <span className="brand-mark" aria-hidden="true">
        <Shield size={18} strokeWidth={2.2} />
      </span>
      {!collapsed ? (
        <span className="brand-copy">
          <strong>SENTINEL</strong>
          <small>THREAT INTELLIGENCE</small>
        </span>
      ) : null}
    </a>
  );
}

function NavigationLinks({
  activeView,
  collapsed = false,
  label = "Main navigation",
  onSelect,
}: {
  activeView: View;
  collapsed?: boolean;
  label?: string;
  onSelect: (view: View) => void;
}) {
  return (
    <nav className="side-nav" aria-label={label}>
      {NAVIGATION.map(({ view, label: itemLabel, href, icon: Icon }) => {
        const active = activeView === view;
        return (
          <a
            key={view}
            href={href}
            className={`nav-link${active ? " nav-link-active" : ""}`}
            aria-current={active ? "page" : undefined}
            title={collapsed ? itemLabel : undefined}
            onClick={(event) => {
              event.preventDefault();
              onSelect(view);
            }}
          >
            <Icon size={17} strokeWidth={1.8} aria-hidden="true" />
            {!collapsed ? <span>{itemLabel}</span> : <span className="sr-only">{itemLabel}</span>}
            {active ? <span className="nav-active-mark" aria-hidden="true" /> : null}
          </a>
        );
      })}
    </nav>
  );
}

function DashboardContent() {
  const { view, navigate } = useHashView();
  const { setHelpOpen, theme } = usePreferences();
  const { metrics, offline } = useLiveMetrics();

  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [selectedIncident, setSelectedIncident] = useState<IncidentRow | null>(null);
  const [analyzeOpen, setAnalyzeOpen] = useState(false);

  // Global keyboard shortcuts: 1-4 switch views, ? opens Help dialog.
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.metaKey || event.ctrlKey || event.altKey) return;
      const target = event.target;
      if (
        target instanceof HTMLElement &&
        (target.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName))
      ) {
        return;
      }
      if (event.key === "1") navigate("overview");
      else if (event.key === "2") navigate("detections");
      else if (event.key === "3") navigate("audit");
      else if (event.key === "4") navigate("model-health");
      else if (event.key === "?") {
        event.preventDefault();
        setHelpOpen(true);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [navigate, setHelpOpen]);

  const live = metrics.data;
  const loading = !live && !offline;
  const modelVersion = live?.model.modelVersion ?? "rf-v1.0";
  const meta = VIEW_META[view];

  function handleNavigate(next: View) {
    navigate(next);
    setMobileMenuOpen(false);
  }

  return (
    <div className={`app-shell${sidebarCollapsed ? " app-shell-collapsed" : ""}`}>
      {/* Desktop collapsible sidebar */}
      <aside
        className={`sidebar${sidebarCollapsed ? " sidebar-collapsed" : ""}`}
        aria-label="Workspace sidebar"
      >
        <div className="sidebar-header-row">
          <Brand collapsed={sidebarCollapsed} onNavigate={handleNavigate} />
          <button
            type="button"
            className="sidebar-collapse-btn"
            aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
            aria-expanded={!sidebarCollapsed}
            onClick={() => setSidebarCollapsed((c) => !c)}
            title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            {sidebarCollapsed ? (
              <PanelLeftOpen size={15} aria-hidden="true" />
            ) : (
              <PanelLeftClose size={15} aria-hidden="true" />
            )}
          </button>
        </div>

        {!sidebarCollapsed ? (
          <div className="sidebar-label">WORKSPACE</div>
        ) : (
          <div className="sidebar-label-spacer" />
        )}

        <NavigationLinks activeView={view} collapsed={sidebarCollapsed} onSelect={handleNavigate} />

        <div className="sidebar-spacer" />

        <button
          type="button"
          className="sidebar-support"
          onClick={() => setHelpOpen(true)}
          aria-label="Need a hand? Open guided tour and help"
          title={sidebarCollapsed ? "Need a hand? Open guided tour" : undefined}
        >
          <span className="support-icon" aria-hidden="true">
            <CircleHelp size={16} />
          </span>
          {!sidebarCollapsed ? (
            <>
              <span className="sidebar-support-copy">
                <strong>Need a hand?</strong>
                <small>{offline ? "Explore offline demo" : "Guided tour & shortcuts"}</small>
              </span>
              <ChevronRight size={15} aria-hidden="true" />
            </>
          ) : null}
        </button>

        <WorkspaceFooter offline={offline} modelVersion={modelVersion} />
      </aside>

      {/* Mobile top bar + slide-over navigation drawer */}
      <div className="mobile-header">
        <div className="mobile-header-left">
          <button
            type="button"
            className="mobile-menu-btn"
            aria-label="Open navigation menu"
            aria-expanded={mobileMenuOpen}
            onClick={() => setMobileMenuOpen(true)}
          >
            <Menu size={18} aria-hidden="true" />
          </button>
          <Brand onNavigate={handleNavigate} />
        </div>
        <div className="mobile-header-right">
          <span className={offline ? "env-tag env-tag-demo" : "env-tag env-tag-live"}>
            {offline ? "Demo data" : "Live DB"}
          </span>
        </div>
      </div>

      <Sheet open={mobileMenuOpen} onOpenChange={setMobileMenuOpen}>
        <SheetContent side="left" className="mobile-drawer-sheet">
          <SheetHeader className="sr-only">
            <SheetTitle>Sentinel navigation</SheetTitle>
            <SheetDescription>
              Switch dashboard views or open workspace help and settings.
            </SheetDescription>
          </SheetHeader>
          <div className="mobile-drawer-body">
            <Brand onNavigate={handleNavigate} />
            <div className="sidebar-label">WORKSPACE</div>
            <NavigationLinks
              activeView={view}
              label="Mobile navigation"
              onSelect={handleNavigate}
            />
            <div className="sidebar-spacer" />
            <button
              type="button"
              className="sidebar-support"
              onClick={() => {
                setMobileMenuOpen(false);
                setHelpOpen(true);
              }}
            >
              <span className="support-icon" aria-hidden="true">
                <CircleHelp size={16} />
              </span>
              <span className="sidebar-support-copy">
                <strong>Need a hand?</strong>
                <small>{offline ? "Explore offline demo" : "Guided tour & shortcuts"}</small>
              </span>
              <ChevronRight size={15} aria-hidden="true" />
            </button>
            <WorkspaceFooter offline={offline} modelVersion={modelVersion} />
          </div>
        </SheetContent>
      </Sheet>

      <main className="dashboard-main">
        <header className="page-header">
          <div className="page-heading-copy">
            <div className="breadcrumb" aria-label="Breadcrumb">
              <span>SECURITY OPERATIONS</span>
              <span className="breadcrumb-slash" aria-hidden="true">
                /
              </span>
              <span>{meta.crumb}</span>
            </div>
            <div className="title-line">
              <h1>{meta.title}</h1>
              <span className={offline ? "env-tag env-tag-demo" : "env-tag env-tag-live"}>
                {offline ? "Demo data" : "Live DB"}
              </span>
              <span className="model-version-chip" title="Active model version">
                {modelVersion}
              </span>
            </div>
            <p>{meta.subtitle}</p>
          </div>

          <div className="header-actions">
            <TopBarWidgets offline={offline} onSelectIncident={setSelectedIncident} />
          </div>
        </header>

        {view === "overview" ? (
          <OverviewView
            metrics={live}
            metricsLoading={loading}
            metricsFetching={metrics.isFetching}
            metricsError={metrics.error}
            offline={offline}
            onRetry={() => void metrics.refetch()}
            onSelectIncident={setSelectedIncident}
            onNavigateDetections={() => handleNavigate("detections")}
            onNavigateAudit={() => handleNavigate("audit")}
            onOpenAnalyze={() => setAnalyzeOpen(true)}
          />
        ) : null}

        {view === "detections" ? (
          <DetectionsView
            offline={offline}
            onSelectIncident={setSelectedIncident}
            onOpenAnalyze={() => setAnalyzeOpen(true)}
          />
        ) : null}

        {view === "audit" ? <AuditView offline={offline} /> : null}

        {view === "model-health" ? <ModelHealthView offline={offline} /> : null}

        <footer className="dashboard-footer">
          <span>
            <Shield size={13} aria-hidden="true" /> Sentinel threat intelligence workspace
          </span>
          <span>
            {offline
              ? "Offline demo fallback · API unreachable"
              : `${live?.model.selectedModel ?? "Random Forest"} (${modelVersion}) · SHA-256 append-only ledger`}
          </span>
        </footer>
      </main>

      <IncidentDrawer
        incident={selectedIncident}
        offline={offline}
        onClose={() => setSelectedIncident(null)}
        onOpenAudit={() => {
          setSelectedIncident(null);
          handleNavigate("audit");
        }}
        onStatusUpdated={(id, nextStatus, blockIndex, by) => {
          setSelectedIncident((current) =>
            current && current.id === id
              ? {
                  ...current,
                  status: nextStatus,
                  statusBlockIndex: blockIndex,
                  statusChangedAt: new Date().toISOString(),
                  statusChangedBy: by,
                }
              : current,
          );
        }}
      />

      <AnalyzeFlowDialog
        open={analyzeOpen}
        onOpenChange={setAnalyzeOpen}
        offline={offline}
        onOpenAudit={() => handleNavigate("audit")}
      />
      <HelpDialog offline={offline} onNavigate={handleNavigate} />
      <SettingsDialog offline={offline} modelVersion={modelVersion} />
      <Toaster position="bottom-right" theme={theme} richColors closeButton />
    </div>
  );
}

export function DashboardShell() {
  return (
    <PreferencesProvider>
      <IntegrityProvider>
        <DashboardContent />
      </IntegrityProvider>
    </PreferencesProvider>
  );
}
