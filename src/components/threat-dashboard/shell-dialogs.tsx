import { useState } from "react";
import {
  ArrowRight,
  BookOpen,
  Boxes,
  BrainCircuit,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  Keyboard,
  Loader2,
  Moon,
  Play,
  Radar,
  Settings,
  Sun,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import type { View } from "@/hooks/use-hash-view";
import { usePreferences, type RefreshSetting } from "@/hooks/use-preferences";
import { useSimulation } from "@/hooks/use-threat-data";

const TOUR_STEPS: {
  title: string;
  summary: string;
  detail: string;
  view: View;
  actionLabel: string;
  icon: typeof Play;
}[] = [
  {
    title: "1. Simulate live traffic",
    summary: "Score network flows through the trained Random Forest model.",
    detail:
      "Click Run simulation to send 20 UNSW-NB15-style traffic flows through the classifier. Any flow scoring at least 50% attack probability is appended to the SHA-256 hash chain.",
    view: "overview",
    actionLabel: "Go to Overview",
    icon: Play,
  },
  {
    title: "2. Read & triage detections",
    summary: "Filter, sort, inspect, and contain detected incidents.",
    detail:
      "Open Detections to filter by severity or status, sort by any column, inspect full block metadata in the slide-over drawer, and toggle Open / Contained by appending a status_change block.",
    view: "detections",
    actionLabel: "Open Detections",
    icon: Radar,
  },
  {
    title: "3. Verify the audit ledger",
    summary: "Recompute every SHA-256 hash and parent link in the chain.",
    detail:
      "Visit Audit ledger to inspect raw block JSON, copy block hashes, export the full chain, and run Verify integrity to confirm zero tampering across all blocks.",
    view: "audit",
    actionLabel: "Open Audit ledger",
    icon: Boxes,
  },
  {
    title: "4. Check model health",
    summary: "Compare classifier metrics and monitor attack-rate drift.",
    detail:
      "Open Model health to inspect model version, dataset provenance, artifact size, Random Forest vs Logistic Regression vs Naive Bayes metrics, confusion matrix, top 10 features, and live drift.",
    view: "model-health",
    actionLabel: "Open Model health",
    icon: BrainCircuit,
  },
];

const REFRESH_OPTIONS: { value: RefreshSetting; label: string }[] = [
  { value: 5, label: "Every 5s" },
  { value: 15, label: "Every 15s" },
  { value: 30, label: "Every 30s" },
  { value: 0, label: "Off" },
];

type HelpDialogProps = {
  offline: boolean;
  onNavigate: (view: View) => void;
};

export function HelpDialog({ offline, onNavigate }: HelpDialogProps) {
  const { helpOpen, setHelpOpen } = usePreferences();
  const simulation = useSimulation();
  const [step, setStep] = useState(0);
  const current = TOUR_STEPS[step]!;
  const StepIcon = current.icon;

  return (
    <Dialog open={helpOpen} onOpenChange={setHelpOpen}>
      <DialogContent className="sentinel-dialog sm:max-w-xl" aria-label="Sentinel help and guided tour">
        <DialogHeader>
          <DialogTitle>Guided tour &amp; workspace help</DialogTitle>
          <DialogDescription>
            Walk through the four core security workflows, keyboard shortcuts, and project documentation.
          </DialogDescription>
        </DialogHeader>

        <div className="tour-steps-nav" role="tablist" aria-label="Guided tour steps">
          {TOUR_STEPS.map((item, idx) => (
            <button
              key={item.title}
              type="button"
              role="tab"
              aria-selected={step === idx}
              className={`tour-step-tab${step === idx ? " tour-step-tab-active" : ""}`}
              onClick={() => setStep(idx)}
            >
              Step {idx + 1}
            </button>
          ))}
        </div>

        <div className="tour-card" role="tabpanel">
          <div className="tour-card-head">
            <span className="tour-step-icon" aria-hidden="true">
              <StepIcon size={16} />
            </span>
            <div>
              <h3>{current.title}</h3>
              <p>{current.summary}</p>
            </div>
          </div>
          <p className="tour-card-body">{current.detail}</p>
          <div className="tour-card-footer">
            <div className="tour-pager">
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="action-button"
                disabled={step === 0}
                onClick={() => setStep((s) => Math.max(0, s - 1))}
              >
                <ChevronLeft size={14} aria-hidden="true" /> Previous
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="action-button"
                disabled={step === TOUR_STEPS.length - 1}
                onClick={() => setStep((s) => Math.min(TOUR_STEPS.length - 1, s + 1))}
              >
                Next <ChevronRight size={14} aria-hidden="true" />
              </Button>
            </div>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="action-button"
              onClick={() => {
                onNavigate(current.view);
                setHelpOpen(false);
              }}
            >
              <span>{current.actionLabel}</span>
              <ArrowRight size={13} aria-hidden="true" />
            </Button>
          </div>
        </div>

        <div className="help-shortcuts">
          <div className="help-section-label">
            <Keyboard size={14} aria-hidden="true" />
            <span>Keyboard shortcuts</span>
          </div>
          <ul className="shortcut-list">
            <li>
              <span>Focus global incident search</span>
              <span><kbd>Ctrl</kbd> / <kbd>⌘</kbd> + <kbd>K</kbd></span>
            </li>
            <li>
              <span>Close active drawer, menu, or dialog</span>
              <span><kbd>Esc</kbd></span>
            </li>
            <li>
              <span>Navigate views via browser history</span>
              <span><kbd>Alt</kbd> + <kbd>←</kbd> / <kbd>→</kbd></span>
            </li>
          </ul>
        </div>

        <div className="help-dialog-actions">
          <a
            href="/api/readme"
            target="_blank"
            rel="noopener noreferrer"
            className="readme-link"
          >
            <BookOpen size={14} aria-hidden="true" />
            <span>Read project README</span>
            <ExternalLink size={12} aria-hidden="true" />
          </a>
          <Button
            type="button"
            variant="ghost"
            className="action-button action-button-primary"
            disabled={offline || simulation.isPending}
            onClick={() => simulation.mutate(20)}
          >
            {simulation.isPending ? (
              <Loader2 size={14} className="spin" aria-hidden="true" />
            ) : (
              <Play size={14} aria-hidden="true" />
            )}
            <span>{simulation.isPending ? "Running simulation…" : "Run demo simulation"}</span>
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

type SettingsDialogProps = {
  offline: boolean;
  modelVersion: string;
};

export function SettingsDialog({ offline, modelVersion }: SettingsDialogProps) {
  const { settingsOpen, setSettingsOpen, theme, setTheme, refreshSeconds, setRefreshSeconds } =
    usePreferences();

  return (
    <Dialog open={settingsOpen} onOpenChange={setSettingsOpen}>
      <DialogContent className="sentinel-dialog sm:max-w-md" aria-label="Workspace settings">
        <DialogHeader>
          <DialogTitle>Workspace settings</DialogTitle>
          <DialogDescription>
            Preferences are saved locally in your browser.
          </DialogDescription>
        </DialogHeader>

        <div className="settings-section">
          <div className="settings-row-info">
            <strong>Environment</strong>
            <span className={offline ? "env-tag env-tag-demo" : "env-tag env-tag-live"}>
              {offline ? "Demo data" : "Live DB"}
            </span>
          </div>
          <div className="settings-row-info">
            <strong>Active model</strong>
            <span className="font-mono text-xs">{modelVersion}</span>
          </div>
        </div>

        <div className="settings-section">
          <strong className="settings-group-label">Appearance</strong>
          <div className="segmented-group" role="radiogroup" aria-label="Theme">
            <button
              type="button"
              role="radio"
              aria-checked={theme === "dark"}
              className={`segmented-btn${theme === "dark" ? " segmented-btn-active" : ""}`}
              onClick={() => setTheme("dark")}
            >
              <Moon size={14} aria-hidden="true" /> Dark
            </button>
            <button
              type="button"
              role="radio"
              aria-checked={theme === "light"}
              className={`segmented-btn${theme === "light" ? " segmented-btn-active" : ""}`}
              onClick={() => setTheme("light")}
            >
              <Sun size={14} aria-hidden="true" /> Light
            </button>
          </div>
        </div>

        <div className="settings-section">
          <strong className="settings-group-label">Auto-refresh interval</strong>
          <div className="segmented-group" role="radiogroup" aria-label="Auto-refresh interval">
            {REFRESH_OPTIONS.map((opt) => (
              <button
                key={opt.value}
                type="button"
                role="radio"
                aria-checked={refreshSeconds === opt.value}
                className={`segmented-btn${refreshSeconds === opt.value ? " segmented-btn-active" : ""}`}
                onClick={() => setRefreshSeconds(opt.value)}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

type WorkspaceMenuProps = {
  offline: boolean;
  modelVersion: string;
};

export function WorkspaceFooter({ offline, modelVersion }: WorkspaceMenuProps) {
  const { theme, setTheme, setSettingsOpen } = usePreferences();

  return (
    <div className="sidebar-footer">
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button
            type="button"
            className="workspace-menu-trigger"
            aria-label="Open workspace menu"
          >
            <span className="avatar-mark" aria-hidden="true">S</span>
            <span className="account-copy">
              <strong>Security team</strong>
              <small>{offline ? "Offline demo" : "Live workspace"}</small>
            </span>
            <ChevronDown size={14} aria-hidden="true" />
          </button>
        </DropdownMenuTrigger>
        <DropdownMenuContent side="top" align="start" className="w-60">
          <DropdownMenuLabel className="workspace-menu-meta">
            <div className="workspace-menu-row">
              <span>Environment</span>
              <span className={offline ? "env-tag env-tag-demo" : "env-tag env-tag-live"}>
                {offline ? "Demo data" : "Live DB"}
              </span>
            </div>
            <div className="workspace-menu-row">
              <span>Model</span>
              <code className="font-mono text-xs">{modelVersion}</code>
            </div>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem
            onSelect={(event) => {
              event.preventDefault();
              setTheme(theme === "dark" ? "light" : "dark");
            }}
          >
            {theme === "dark" ? <Sun size={14} aria-hidden="true" /> : <Moon size={14} aria-hidden="true" />}
            <span>Switch to {theme === "dark" ? "light" : "dark"} theme</span>
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => setSettingsOpen(true)}>
            <Settings size={14} aria-hidden="true" />
            <span>Workspace settings</span>
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <button
        type="button"
        className="settings-icon-btn"
        onClick={() => setSettingsOpen(true)}
        aria-label="Open workspace settings"
      >
        <Settings size={16} aria-hidden="true" />
      </button>
    </div>
  );
}
