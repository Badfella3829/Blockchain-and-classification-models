import { Fragment, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import {
  AlertTriangle,
  Check,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Copy,
  FileJson,
  Loader2,
  RefreshCw,
  ShieldCheck,
  ShieldX,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { usePreferences } from "@/hooks/use-preferences";
import { useIntegrity } from "@/hooks/use-threat-data";
import { api, blocksQuery, downloadJson } from "@/lib/api";
import type { LedgerBlock } from "@/lib/threat/types";
import { demoBlocks } from "./demo-data";
import { relativeTime, shortHash } from "./incident-rows";

const PAGE_SIZE = 15;

type AuditViewProps = {
  offline: boolean;
};

function blockEventMeta(block: LedgerBlock): { kind: string; summary: string } {
  if (typeof block.event === "string") {
    return { kind: "Genesis", summary: block.event };
  }
  if (block.event && typeof block.event === "object" && !Array.isArray(block.event)) {
    const type = String(block.event["type"] ?? "");
    if (type === "status_change") {
      const id = String(block.event["incident_id"] ?? "Unknown");
      const status = String(block.event["new_status"] ?? "Updated");
      const by = String(block.event["by"] ?? "Security team");
      return { kind: "Status change", summary: `${id} → ${status} by ${by}` };
    }
    if (type === "detection") {
      const id = String(block.event["event_id"] ?? "");
      const sev = String(block.event["severity"] ?? "");
      const cat = String(block.event["category"] ?? "Detection");
      return { kind: "Detection", summary: `${sev} ${cat} (${id})`.trim() };
    }
  }
  return { kind: "Record", summary: "Ledger entry" };
}

export function AuditView({ offline }: AuditViewProps) {
  const { refetchInterval } = usePreferences();
  const integrity = useIntegrity();
  const exportChainFn = useServerFn(api.exportChain);
  const [page, setPage] = useState(1);
  const [expanded, setExpanded] = useState<Record<number, boolean>>({});
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);

  const query = useQuery({
    ...blocksQuery(page, PAGE_SIZE, refetchInterval),
    enabled: !offline,
  });

  const blocks: LedgerBlock[] = offline
    ? demoBlocks.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)
    : (query.data?.items ?? []);

  const total = offline ? demoBlocks.length : (query.data?.total ?? 0);
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const verification = integrity.result;

  function toggleExpand(blockIndex: number) {
    setExpanded((prev) => ({ ...prev, [blockIndex]: !prev[blockIndex] }));
  }

  async function copyValue(key: string, label: string, text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      toast.success(`${label} copied`);
      setTimeout(() => setCopiedKey((prev) => (prev === key ? null : prev)), 1600);
    } catch {
      toast.error("Clipboard unavailable");
    }
  }

  async function handleExportJson() {
    if (offline) {
      downloadJson(demoBlocks, "sentinel-demo-chain.json");
      toast.success(`Exported ${demoBlocks.length} demo blocks`);
      return;
    }
    setExporting(true);
    try {
      const all = await exportChainFn();
      downloadJson(all, "sentinel-audit-ledger.json");
      toast.success(`Exported ${all.length} blocks as JSON`);
    } catch (error) {
      toast.error("Chain export failed", {
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
      <div className="view-toolbar">
        <div className="view-toolbar-meta">
          <span className="tabular-nums">{total.toLocaleString()} blocks · newest first</span>
          <span aria-hidden="true">·</span>
          <span>
            {verification
              ? `Last verified ${relativeTime(verification.checkedAt)} (${new Date(verification.checkedAt).toLocaleTimeString()})`
              : "Not verified yet this session"}
          </span>
        </div>
        <div className="view-toolbar-actions">
          <Button
            variant="ghost"
            className="action-button action-button-primary"
            type="button"
            disabled={offline || integrity.isPending}
            onClick={() => integrity.verify()}
          >
            {integrity.isPending ? (
              <Loader2 size={15} className="spin" aria-hidden="true" />
            ) : (
              <ShieldCheck size={15} aria-hidden="true" />
            )}
            <span>{integrity.isPending ? "Verifying…" : "Verify integrity"}</span>
          </Button>
          <Button
            variant="ghost"
            className="export-button"
            type="button"
            disabled={exporting}
            onClick={() => void handleExportJson()}
          >
            {exporting ? (
              <Loader2 size={15} className="spin" aria-hidden="true" />
            ) : (
              <FileJson size={15} aria-hidden="true" />
            )}
            <span>Export JSON</span>
          </Button>
        </div>
      </div>

      {offline ? (
        <div className="status-banner status-banner-error" role="alert">
          <AlertTriangle size={16} aria-hidden="true" />
          <p>
            <strong>Offline demo fallback.</strong>{" "}
            <span>Showing sample ledger blocks. Cryptographic integrity verification requires the live API.</span>
          </p>
        </div>
      ) : query.isError ? (
        <div className="status-banner status-banner-error" role="alert">
          <AlertTriangle size={16} aria-hidden="true" />
          <p>
            <strong>Could not load ledger blocks.</strong>{" "}
            <span>{query.error instanceof Error ? query.error.message : "Ledger service unavailable."}</span>
          </p>
          <Button variant="ghost" className="action-button" type="button" onClick={() => void query.refetch()}>
            <RefreshCw size={14} aria-hidden="true" /> Retry
          </Button>
        </div>
      ) : null}

      {verification ? (
        <div
          className={`status-banner ${verification.valid ? "status-banner-ok" : "status-banner-error"}`}
          role={verification.valid ? "status" : "alert"}
        >
          {verification.valid ? (
            <ShieldCheck size={16} aria-hidden="true" />
          ) : (
            <ShieldX size={16} aria-hidden="true" />
          )}
          <p>
            {verification.valid ? (
              <>
                <strong>Chain valid.</strong>{" "}
                <span>
                  All {verification.length.toLocaleString()} SHA-256 block hashes and parent links verified intact
                  at {new Date(verification.checkedAt).toLocaleTimeString()}.
                </span>
              </>
            ) : (
              <>
                <strong>Tampering detected at block #{verification.badIndex}.</strong>{" "}
                <span>
                  {verification.reason ?? "Hash mismatch."} Highlighted blocks from #{verification.badIndex} onward
                  cannot be trusted.
                </span>
              </>
            )}
          </p>
        </div>
      ) : null}

      <section className="panel incidents-panel" aria-labelledby="audit-ledger-heading">
        <div className="panel-heading incidents-heading">
          <div>
            <h2 id="audit-ledger-heading">Hash-linked audit blocks</h2>
            <p>
              Append-only SHA-256 ledger. Click any block to expand its full JSON payload.
            </p>
          </div>
        </div>

        {!offline && query.isLoading ? (
          <div className="table-skeleton" aria-label="Loading audit blocks">
            {Array.from({ length: 6 }, (_, i) => (
              <span className="skeleton-line" key={i} />
            ))}
          </div>
        ) : blocks.length === 0 ? (
          <div className="empty-table">No blocks recorded on the ledger yet.</div>
        ) : (
          <div
            className="table-scroll"
            role="region"
            aria-label="Audit ledger blocks; scroll horizontally to see all columns"
            tabIndex={0}
          >
            <table className="incident-table audit-table">
              <thead>
                <tr>
                  <th scope="col"><span className="sr-only">Expand</span></th>
                  <th scope="col">Index</th>
                  <th scope="col">Time</th>
                  <th scope="col">Event type</th>
                  <th scope="col">Summary</th>
                  <th scope="col">Hash</th>
                  <th scope="col">Previous hash</th>
                </tr>
              </thead>
              <tbody>
                {blocks.map((block) => {
                  const meta = blockEventMeta(block);
                  const isOpen = Boolean(expanded[block.index]);
                  const isTampered = Boolean(
                    verification &&
                      !verification.valid &&
                      verification.badIndex !== null &&
                      block.index >= verification.badIndex,
                  );
                  const isFirstTampered = Boolean(
                    verification && !verification.valid && verification.badIndex === block.index,
                  );
                  const hashKey = `hash-${block.index}`;
                  const prevKey = `prev-${block.index}`;
                  return (
                    <Fragment key={block.index}>
                      <tr className={isTampered ? "audit-row-tampered" : undefined}>
                        <td>
                          <button
                            type="button"
                            className="expand-btn"
                            aria-expanded={isOpen}
                            aria-controls={`block-json-${block.index}`}
                            aria-label={`${isOpen ? "Collapse" : "Expand"} block #${block.index}`}
                            onClick={() => toggleExpand(block.index)}
                          >
                            {isOpen ? (
                              <ChevronDown size={15} aria-hidden="true" />
                            ) : (
                              <ChevronRight size={15} aria-hidden="true" />
                            )}
                          </button>
                        </td>
                        <td className="font-mono tabular-nums font-medium">
                          <span>#{block.index}</span>
                          {isTampered ? (
                            <span className="tampered-label">
                              {isFirstTampered ? "Tampered" : "Broken link"}
                            </span>
                          ) : null}
                        </td>
                        <td className="time-cell tabular-nums" title={block.timestamp}>
                          {relativeTime(block.timestamp)}
                        </td>
                        <td>
                          <span className={`event-kind event-kind-${meta.kind.toLowerCase().replace(/\s+/g, "-")}`}>
                            {meta.kind}
                          </span>
                        </td>
                        <td className="audit-summary-cell">{meta.summary}</td>
                        <td>
                          <div className="hash-cell">
                            <code title={block.hash}>{shortHash(block.hash)}</code>
                            <button
                              type="button"
                              className="copy-icon-btn"
                              onClick={() => void copyValue(hashKey, `Block #${block.index} hash`, block.hash)}
                              aria-label={`Copy hash for block #${block.index}`}
                            >
                              {copiedKey === hashKey ? <Check size={12} aria-hidden="true" /> : <Copy size={12} aria-hidden="true" />}
                            </button>
                          </div>
                        </td>
                        <td>
                          <div className="hash-cell">
                            <code title={block.previous_hash}>{shortHash(block.previous_hash)}</code>
                            <button
                              type="button"
                              className="copy-icon-btn"
                              onClick={() => void copyValue(prevKey, `Block #${block.index} previous hash`, block.previous_hash)}
                              aria-label={`Copy previous hash for block #${block.index}`}
                            >
                              {copiedKey === prevKey ? <Check size={12} aria-hidden="true" /> : <Copy size={12} aria-hidden="true" />}
                            </button>
                          </div>
                        </td>
                      </tr>
                      {isOpen ? (
                        <tr id={`block-json-${block.index}`} className="audit-json-row">
                          <td colSpan={7}>
                            <div className="audit-json-panel">
                              <div className="audit-json-header">
                                <span className="font-mono">Block #{block.index} · {block.timestamp}</span>
                                <div className="audit-json-actions">
                                  <button
                                    type="button"
                                    className="copy-mini-btn"
                                    onClick={() => void copyValue(`full-hash-${block.index}`, "Full block hash", block.hash)}
                                  >
                                    <Copy size={12} aria-hidden="true" /> Copy hash
                                  </button>
                                  <button
                                    type="button"
                                    className="copy-mini-btn"
                                    onClick={() =>
                                      void copyValue(
                                        `full-json-${block.index}`,
                                        `Block #${block.index} JSON`,
                                        JSON.stringify(block, null, 2),
                                      )
                                    }
                                  >
                                    <Copy size={12} aria-hidden="true" /> Copy JSON
                                  </button>
                                </div>
                              </div>
                              <pre className="audit-json-pre">{JSON.stringify(block, null, 2)}</pre>
                            </div>
                          </td>
                        </tr>
                      ) : null}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        <div className="pagination-bar">
          <span className="tabular-nums">
            Showing {startItem}–{endItem} of {total.toLocaleString()} blocks · Page {page} of {pageCount}
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
              <ChevronLeft size={14} aria-hidden="true" /> Newer
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="inspect-button"
              type="button"
              disabled={page >= pageCount}
              onClick={() => setPage((p) => Math.min(pageCount, p + 1))}
            >
              Older <ChevronRight size={14} aria-hidden="true" />
            </Button>
          </div>
        </div>
      </section>
    </div>
  );
}
