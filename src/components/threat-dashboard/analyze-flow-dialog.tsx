import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ArrowRight,
  CheckCircle2,
  FlaskConical,
  Loader2,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { api, type FlowAnalysisResponse } from "@/lib/api";
import { shortHash } from "./incident-rows";

type FlowForm = {
  source: string;
  category: string;
  proto: string;
  service: string;
  state: string;
  dur: number;
  spkts: number;
  dpkts: number;
  sbytes: number;
  dbytes: number;
  rate: number;
  sttl: number;
  dttl: number;
  sload: number;
  dload: number;
  smean: number;
  dmean: number;
  ct_srv_src: number;
  ct_dst_ltm: number;
};

type Preset = {
  id: string;
  label: string;
  hint: string;
  values: FlowForm;
};

const PRESETS: Preset[] = [
  {
    id: "dos",
    label: "DoS flood",
    hint: "High TTL, asymmetric packets, elevated service rate",
    values: {
      source: "198.51.100.44",
      category: "DoS",
      proto: "udp",
      service: "http",
      state: "INT",
      dur: 0.069,
      spkts: 20,
      dpkts: 3,
      sbytes: 8580,
      dbytes: 60,
      rate: 332.27,
      sttl: 254,
      dttl: 252,
      sload: 991612,
      dload: 6934,
      smean: 429,
      dmean: 20,
      ct_srv_src: 21,
      ct_dst_ltm: 4,
    },
  },
  {
    id: "recon",
    label: "Port scan",
    hint: "Micro-duration burst, zero response bytes",
    values: {
      source: "203.0.113.71",
      category: "Reconnaissance",
      proto: "tcp",
      service: "-",
      state: "REQ",
      dur: 0.00009,
      spkts: 2,
      dpkts: 0,
      sbytes: 350,
      dbytes: 0,
      rate: 21495.9,
      sttl: 254,
      dttl: 0,
      sload: 30094244,
      dload: 0,
      smean: 175,
      dmean: 0,
      ct_srv_src: 15,
      ct_dst_ltm: 5,
    },
  },
  {
    id: "exploit",
    label: "HTTP exploit",
    hint: "Payload delivery over TCP/HTTP with elevated dttl",
    values: {
      source: "10.28.14.92",
      category: "Exploits",
      proto: "tcp",
      service: "http",
      state: "FIN",
      dur: 0.719,
      spkts: 18,
      dpkts: 20,
      sbytes: 3093,
      dbytes: 2085,
      rate: 52.86,
      sttl: 62,
      dttl: 252,
      sload: 34420,
      dload: 23203,
      smean: 172,
      dmean: 104,
      ct_srv_src: 5,
      ct_dst_ltm: 4,
    },
  },
  {
    id: "normal",
    label: "Normal HTTPS",
    hint: "Balanced bidirectional session with standard TTL",
    values: {
      source: "10.28.4.19",
      category: "Normal",
      proto: "tcp",
      service: "http",
      state: "CON",
      dur: 0.696,
      spkts: 14,
      dpkts: 34,
      sbytes: 1469,
      dbytes: 15271,
      rate: 68.92,
      sttl: 31,
      dttl: 29,
      sload: 16874,
      dload: 175411,
      smean: 105,
      dmean: 449,
      ct_srv_src: 4,
      ct_dst_ltm: 2,
    },
  },
];

type AnalyzeFlowDialogProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  offline: boolean;
  onOpenAudit: () => void;
};

export function AnalyzeFlowDialog({
  open,
  onOpenChange,
  offline,
  onOpenAudit,
}: AnalyzeFlowDialogProps) {
  const queryClient = useQueryClient();
  const [activePreset, setActivePreset] = useState<string>("dos");
  const [form, setForm] = useState<FlowForm>(PRESETS[0]!.values);
  const [recordToLedger, setRecordToLedger] = useState(true);
  const [result, setResult] = useState<Extract<FlowAnalysisResponse, { ok: true }> | null>(null);

  const mutation = useMutation({
    mutationFn: () =>
      api.analyzeFlow({
        source: form.source,
        category: form.category,
        recordToLedger,
        features: {
          dur: form.dur,
          proto: form.proto,
          service: form.service,
          state: form.state,
          spkts: form.spkts,
          dpkts: form.dpkts,
          sbytes: form.sbytes,
          dbytes: form.dbytes,
          rate: form.rate,
          sttl: form.sttl,
          dttl: form.dttl,
          sload: form.sload,
          dload: form.dload,
          smean: form.smean,
          dmean: form.dmean,
          ct_srv_src: form.ct_srv_src,
          ct_dst_ltm: form.ct_dst_ltm,
        },
      }),
    onSuccess: (res) => {
      if (!res.ok) {
        toast.error("Flow analysis failed", { description: res.message });
        return;
      }
      setResult(res);
      if (res.recorded) {
        toast.success(`Threat recorded at block #${res.blockIndex}`, {
          description: `${res.severity} (${res.confidence.toFixed(1)}%) appended to the SHA-256 ledger.`,
        });
        void queryClient.invalidateQueries({ queryKey: ["threat"] });
      }
    },
    onError: (err) => {
      toast.error("Flow analysis failed", {
        description: err instanceof Error ? err.message : String(err),
      });
    },
  });

  function applyPreset(preset: Preset) {
    setActivePreset(preset.id);
    setForm(preset.values);
    setResult(null);
  }

  function updateNumber(field: keyof FlowForm, raw: string) {
    const parsed = Number(raw);
    setForm((prev) => ({ ...prev, [field]: Number.isFinite(parsed) ? parsed : 0 }));
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        className="sentinel-dialog sm:max-w-2xl max-h-[90vh] overflow-y-auto"
        aria-label="Live network flow analyzer"
      >
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FlaskConical size={17} aria-hidden="true" />
            <span>Live flow analyzer</span>
          </DialogTitle>
          <DialogDescription>
            Submit custom network telemetry to the deployed Random Forest classifier via{" "}
            <code className="font-mono text-xs">POST /api/predict</code> and inspect standardized
            signal drivers.
          </DialogDescription>
        </DialogHeader>

        <div className="analyzer-presets" role="group" aria-label="Traffic flow presets">
          {PRESETS.map((preset) => (
            <button
              key={preset.id}
              type="button"
              className={`analyzer-preset-btn${activePreset === preset.id ? " analyzer-preset-active" : ""}`}
              onClick={() => applyPreset(preset)}
            >
              <strong>{preset.label}</strong>
              <small>{preset.hint}</small>
            </button>
          ))}
        </div>

        <form
          className="analyzer-form"
          onSubmit={(event) => {
            event.preventDefault();
            mutation.mutate();
          }}
        >
          <div className="analyzer-grid">
            <div className="analyzer-field">
              <Label htmlFor="flow-source">Source IP</Label>
              <Input
                id="flow-source"
                value={form.source}
                onChange={(e) => setForm((p) => ({ ...p, source: e.target.value }))}
                className="font-mono text-xs"
              />
            </div>
            <div className="analyzer-field">
              <Label htmlFor="flow-category">Category label</Label>
              <Input
                id="flow-category"
                value={form.category}
                onChange={(e) => setForm((p) => ({ ...p, category: e.target.value }))}
              />
            </div>
            <div className="analyzer-field">
              <Label htmlFor="flow-proto">Protocol</Label>
              <Select
                value={form.proto}
                onValueChange={(v) => setForm((p) => ({ ...p, proto: v }))}
              >
                <SelectTrigger id="flow-proto">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="tcp">TCP</SelectItem>
                  <SelectItem value="udp">UDP</SelectItem>
                  <SelectItem value="icmp">ICMP</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="analyzer-field">
              <Label htmlFor="flow-service">Service</Label>
              <Select
                value={form.service}
                onValueChange={(v) => setForm((p) => ({ ...p, service: v }))}
              >
                <SelectTrigger id="flow-service">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="http">HTTP</SelectItem>
                  <SelectItem value="dns">DNS</SelectItem>
                  <SelectItem value="ftp">FTP</SelectItem>
                  <SelectItem value="smtp">SMTP</SelectItem>
                  <SelectItem value="-">Other (-)</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="analyzer-field">
              <Label htmlFor="flow-sttl">Source TTL (sttl)</Label>
              <Input
                id="flow-sttl"
                type="number"
                value={form.sttl}
                onChange={(e) => updateNumber("sttl", e.target.value)}
                className="font-mono tabular-nums"
              />
            </div>
            <div className="analyzer-field">
              <Label htmlFor="flow-dttl">Dest TTL (dttl)</Label>
              <Input
                id="flow-dttl"
                type="number"
                value={form.dttl}
                onChange={(e) => updateNumber("dttl", e.target.value)}
                className="font-mono tabular-nums"
              />
            </div>
            <div className="analyzer-field">
              <Label htmlFor="flow-sbytes">Source bytes</Label>
              <Input
                id="flow-sbytes"
                type="number"
                value={form.sbytes}
                onChange={(e) => updateNumber("sbytes", e.target.value)}
                className="font-mono tabular-nums"
              />
            </div>
            <div className="analyzer-field">
              <Label htmlFor="flow-dbytes">Dest bytes</Label>
              <Input
                id="flow-dbytes"
                type="number"
                value={form.dbytes}
                onChange={(e) => updateNumber("dbytes", e.target.value)}
                className="font-mono tabular-nums"
              />
            </div>
            <div className="analyzer-field">
              <Label htmlFor="flow-rate">Packet rate (/s)</Label>
              <Input
                id="flow-rate"
                type="number"
                step="any"
                value={form.rate}
                onChange={(e) => updateNumber("rate", e.target.value)}
                className="font-mono tabular-nums"
              />
            </div>
            <div className="analyzer-field">
              <Label htmlFor="flow-dur">Duration (s)</Label>
              <Input
                id="flow-dur"
                type="number"
                step="any"
                value={form.dur}
                onChange={(e) => updateNumber("dur", e.target.value)}
                className="font-mono tabular-nums"
              />
            </div>
          </div>

          <div className="analyzer-submit-row">
            <label className="analyzer-checkbox-row" htmlFor="record-to-ledger">
              <Checkbox
                id="record-to-ledger"
                checked={recordToLedger}
                onCheckedChange={(checked) => setRecordToLedger(checked === true)}
              />
              <span>Append detected attacks to the SHA-256 audit ledger</span>
            </label>
            <Button
              type="submit"
              variant="ghost"
              className="action-button action-button-primary"
              disabled={offline || mutation.isPending}
            >
              {mutation.isPending ? (
                <Loader2 size={14} className="spin" aria-hidden="true" />
              ) : (
                <FlaskConical size={14} aria-hidden="true" />
              )}
              <span>{mutation.isPending ? "Scoring flow…" : "Score flow"}</span>
            </Button>
          </div>
        </form>

        {result ? (
          <div className="analyzer-result" aria-live="polite">
            <div className="analyzer-result-head">
              <div className="analyzer-verdict">
                {result.label === "Attack" ? (
                  <ShieldAlert size={18} className="severity-text-critical" aria-hidden="true" />
                ) : (
                  <ShieldCheck size={18} className="severity-text-low" aria-hidden="true" />
                )}
                <div>
                  <strong>
                    Verdict: {result.label} ({result.confidence.toFixed(1)}% probability)
                  </strong>
                  <small>
                    Severity: {result.severity} · Model {result.modelVersion}
                  </small>
                </div>
              </div>
              {result.recorded && result.blockIndex !== null ? (
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="action-button"
                  onClick={() => {
                    onOpenChange(false);
                    onOpenAudit();
                  }}
                >
                  <CheckCircle2 size={13} aria-hidden="true" />
                  <span>Block #{result.blockIndex}</span>
                  <ArrowRight size={12} aria-hidden="true" />
                </Button>
              ) : null}
            </div>

            <div
              className="analyzer-prob-track"
              aria-label={`Attack probability ${result.confidence.toFixed(1)} percent`}
            >
              <span
                className={
                  result.label === "Attack"
                    ? "analyzer-prob-fill analyzer-prob-attack"
                    : "analyzer-prob-fill analyzer-prob-normal"
                }
                style={{ width: `${Math.min(100, Math.max(2, result.confidence))}%` }}
              />
            </div>

            {result.recorded && result.blockHash ? (
              <div className="analyzer-ledger-proof">
                <span>
                  Recorded as <strong className="font-mono">{result.eventId}</strong>
                </span>
                <code className="font-mono">{shortHash(result.blockHash)}</code>
              </div>
            ) : null}

            <div className="analyzer-signals">
              <span className="analyzer-signals-title">
                Top standardized feature deviations (z-score)
              </span>
              <div className="analyzer-signal-grid">
                {result.signals.map((sig) => (
                  <div key={sig.feature} className="analyzer-signal-cell">
                    <code className="font-mono">{sig.feature}</code>
                    <strong className="tabular-nums">{sig.value.toLocaleString()}</strong>
                    <small className="font-mono tabular-nums">
                      {sig.zScore >= 0 ? "+" : ""}
                      {sig.zScore.toFixed(2)}σ
                    </small>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}
