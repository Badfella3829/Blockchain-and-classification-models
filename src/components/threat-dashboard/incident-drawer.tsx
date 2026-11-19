import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { ArrowRight, Boxes, Check, CheckCircle2, Copy, Loader2, RotateCcw } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { api } from "@/lib/api";
import type { IncidentStatus } from "@/lib/threat/types";
import { relativeTime, type IncidentRow } from "./incident-rows";

type IncidentDrawerProps = {
  incident: IncidentRow | null;
  offline: boolean;
  onClose: () => void;
  onOpenAudit: () => void;
  onStatusUpdated: (id: string, nextStatus: IncidentStatus, blockIndex: number, by: string) => void;
};

export function IncidentDrawer({
  incident,
  offline,
  onClose,
  onOpenAudit,
  onStatusUpdated,
}: IncidentDrawerProps) {
  const queryClient = useQueryClient();
  const [analystName, setAnalystName] = useState("Security team");
  const [pending, setPending] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  async function copyValue(key: string, value: string | null) {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      setCopiedKey(key);
      toast.success("Copied to clipboard");
      setTimeout(() => setCopiedKey((current) => (current === key ? null : current)), 1500);
    } catch {
      toast.error("Copy failed", { description: "Clipboard access was blocked by the browser." });
    }
  }

  async function handleStatusToggle() {
    if (!incident || offline) return;
    const nextStatus: IncidentStatus = incident.status === "Open" ? "Contained" : "Open";
    const actor = analystName.trim() || "Security team";
    setPending(true);
    try {
      const result = await api.postIncidentStatus({
        id: incident.id,
        status: nextStatus,
        by: actor,
      });
      if (!result.ok) {
        toast.error("Status change failed", { description: result.message });
        return;
      }
      onStatusUpdated(incident.id, result.status, result.blockIndex, actor);
      await queryClient.invalidateQueries({ queryKey: ["threat"] });
      toast.success(
        result.status === "Contained"
          ? `${incident.id} marked Contained`
          : `${incident.id} reopened`,
        {
          description: `Appended immutable status_change block #${result.blockIndex} by ${actor}.`,
        },
      );
    } catch (error) {
      toast.error("Status change failed", {
        description: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setPending(false);
    }
  }

  const nextStatus: IncidentStatus = incident?.status === "Open" ? "Contained" : "Open";
  const detectedLabel = incident?.detectedAt
    ? new Date(incident.detectedAt).toLocaleString()
    : (incident?.firstSeen ?? "—");

  return (
    <Sheet open={Boolean(incident)} onOpenChange={(open) => !open && onClose()}>
      <SheetContent side="right" className="incident-drawer-sheet">
        {incident ? (
          <>
            <SheetHeader>
              <div className="drawer-meta-line">
                <span className={`severity-text severity-text-${incident.severity.toLowerCase()}`}>
                  {incident.severity}
                </span>
                <span aria-hidden="true">·</span>
                <span className="font-mono text-xs">{incident.id}</span>
                <span aria-hidden="true">·</span>
                <span className={`status-label status-label-${incident.status.toLowerCase()}`}>
                  {incident.status}
                </span>
              </div>
              <SheetTitle className="drawer-title">{incident.title}</SheetTitle>
              <SheetDescription className="drawer-description">
                {incident.description}
              </SheetDescription>
            </SheetHeader>

            <div className="drawer-body">
              <div className="drawer-section">
                <div className="drawer-section-head">
                  <span className="drawer-section-title">Detection fields</span>
                </div>
                <div className="drawer-facts-grid">
                  <div className="drawer-field">
                    <span>Incident ID</span>
                    <strong className="font-mono tabular-nums">{incident.id}</strong>
                  </div>
                  <div className="drawer-field">
                    <span>Source IP</span>
                    <strong className="font-mono tabular-nums">{incident.source}</strong>
                  </div>
                  <div className="drawer-field">
                    <span>Category</span>
                    <strong>{incident.category}</strong>
                  </div>
                  <div className="drawer-field">
                    <span>Severity</span>
                    <strong
                      className={`severity-text severity-text-${incident.severity.toLowerCase()}`}
                    >
                      {incident.severity}
                    </strong>
                  </div>
                  <div className="drawer-field">
                    <span>Model confidence</span>
                    <strong className="tabular-nums">{incident.confidence.toFixed(2)}%</strong>
                  </div>
                  <div className="drawer-field">
                    <span>Current status</span>
                    <div>
                      <span
                        className={`status-label status-label-${incident.status.toLowerCase()}`}
                      >
                        {incident.status}
                      </span>
                    </div>
                  </div>
                  <div className="drawer-field">
                    <span>Detected at</span>
                    <strong className="tabular-nums">{detectedLabel}</strong>
                  </div>
                  <div className="drawer-field">
                    <span>Model version</span>
                    <strong className="font-mono">{incident.modelVersion ?? "rf-v1.0"}</strong>
                  </div>
                </div>
              </div>

              <div className="drawer-section">
                <div className="drawer-section-head">
                  <span className="drawer-section-title">Recording chain block</span>
                  <button type="button" className="inline-link-btn" onClick={onOpenAudit}>
                    <Boxes size={13} aria-hidden="true" />
                    <span>Open in Audit ledger</span>
                    <ArrowRight size={13} aria-hidden="true" />
                  </button>
                </div>

                <div className="drawer-block-box">
                  <div className="drawer-block-row">
                    <span>Block index</span>
                    <strong className="font-mono tabular-nums">
                      {incident.blockIndex !== null ? `#${incident.blockIndex}` : "Demo only"}
                    </strong>
                  </div>

                  <div className="drawer-hash-block">
                    <div className="drawer-hash-header">
                      <span>SHA-256 block hash</span>
                      {incident.hash ? (
                        <button
                          type="button"
                          className="copy-mini-btn"
                          onClick={() => void copyValue("hash", incident.hash)}
                        >
                          {copiedKey === "hash" ? (
                            <Check size={12} aria-hidden="true" />
                          ) : (
                            <Copy size={12} aria-hidden="true" />
                          )}
                          <span>{copiedKey === "hash" ? "Copied" : "Copy"}</span>
                        </button>
                      ) : null}
                    </div>
                    <code className="drawer-hash-code">
                      {incident.hash ?? "Unavailable in offline demo mode"}
                    </code>
                  </div>

                  <div className="drawer-hash-block">
                    <div className="drawer-hash-header">
                      <span>Previous block hash</span>
                      {incident.previousHash ? (
                        <button
                          type="button"
                          className="copy-mini-btn"
                          onClick={() => void copyValue("prev", incident.previousHash)}
                        >
                          {copiedKey === "prev" ? (
                            <Check size={12} aria-hidden="true" />
                          ) : (
                            <Copy size={12} aria-hidden="true" />
                          )}
                          <span>{copiedKey === "prev" ? "Copied" : "Copy"}</span>
                        </button>
                      ) : null}
                    </div>
                    <code className="drawer-hash-code">
                      {incident.previousHash ?? "Unavailable in offline demo mode"}
                    </code>
                  </div>

                  {incident.statusBlockIndex !== null ? (
                    <div className="drawer-status-audit">
                      <CheckCircle2
                        size={14}
                        className="inline mr-1.5 align-text-bottom"
                        aria-hidden="true"
                      />
                      Latest status recorded in block{" "}
                      <strong className="font-mono">#{incident.statusBlockIndex}</strong> by{" "}
                      <strong>{incident.statusChangedBy ?? "Security team"}</strong>
                      {incident.statusChangedAt
                        ? ` (${relativeTime(incident.statusChangedAt)})`
                        : ""}
                      .
                    </div>
                  ) : null}
                </div>
              </div>

              <div className="drawer-section">
                <div className="drawer-section-head">
                  <span className="drawer-section-title">Append status change</span>
                </div>
                <p className="drawer-helper">
                  The audit ledger is append-only. Changing status appends a new{" "}
                  <code className="font-mono">status_change</code> block rather than editing
                  historical records.
                </p>
                {offline ? (
                  <p className="drawer-offline-note">
                    Status updates require a live API connection and are disabled in offline demo
                    fallback.
                  </p>
                ) : (
                  <div className="drawer-status-form">
                    <label className="analyzer-field">
                      <span>Recorded by</span>
                      <Input
                        value={analystName}
                        onChange={(event) => setAnalystName(event.target.value)}
                        maxLength={40}
                        placeholder="Security team"
                      />
                    </label>
                    <Button
                      type="button"
                      variant="ghost"
                      className={`action-button ${nextStatus === "Contained" ? "action-button-primary" : ""}`}
                      disabled={pending}
                      onClick={() => void handleStatusToggle()}
                    >
                      {pending ? (
                        <Loader2 size={14} className="spin" aria-hidden="true" />
                      ) : nextStatus === "Contained" ? (
                        <CheckCircle2 size={14} aria-hidden="true" />
                      ) : (
                        <RotateCcw size={14} aria-hidden="true" />
                      )}
                      <span>
                        {nextStatus === "Contained" ? "Mark Contained" : "Reopen incident"}
                      </span>
                    </Button>
                  </div>
                )}
              </div>
            </div>
          </>
        ) : null}
      </SheetContent>
    </Sheet>
  );
}
