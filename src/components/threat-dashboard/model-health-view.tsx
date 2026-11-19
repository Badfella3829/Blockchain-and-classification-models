import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  BrainCircuit,
  CheckCircle2,
  Database,
  Gauge,
  HardDrive,
  Info,
  RefreshCw,
  ShieldAlert,
} from "lucide-react";
import { Bar, BarChart, CartesianGrid, XAxis, YAxis } from "recharts";
import { Button } from "@/components/ui/button";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import { usePreferences } from "@/hooks/use-preferences";
import { modelHealthQuery } from "@/lib/api";
import { demoModelHealth } from "./demo-data";
import { formatBytes } from "./incident-rows";
import { MetricCard } from "./metric-card";

const comparisonConfig = {
  accuracy: { label: "Accuracy", color: "var(--chart-1)" },
  precision: { label: "Precision", color: "var(--chart-2)" },
  recall: { label: "Recall", color: "var(--chart-3)" },
  f1: { label: "F1 score", color: "var(--chart-5)" },
} satisfies ChartConfig;

const importanceConfig = {
  importancePct: { label: "Importance (%)", color: "var(--chart-1)" },
} satisfies ChartConfig;

type ModelHealthViewProps = {
  offline: boolean;
};

export function ModelHealthView({ offline }: ModelHealthViewProps) {
  const { refetchInterval } = usePreferences();

  const query = useQuery({
    ...modelHealthQuery(refetchInterval),
    enabled: !offline,
  });

  const data = offline ? demoModelHealth : query.data;
  const loading = !offline && query.isLoading && !data;

  const comparisonData = (data?.comparison ?? []).map((item) => ({
    model: item.model.replace("Logistic Regression", "Logistic Reg."),
    fullName: item.model,
    accuracy: Number((item.accuracy * 100).toFixed(2)),
    precision: Number((item.precision * 100).toFixed(2)),
    recall: Number((item.recall * 100).toFixed(2)),
    f1: Number((item.f1 * 100).toFixed(2)),
  }));

  const importanceData = (data?.featureImportances ?? []).slice(0, 10).map((item) => ({
    feature: item.feature,
    importancePct: Number((item.importance * 100).toFixed(2)),
  }));

  const cm = data?.confusionMatrix;
  const tn = cm?.[0]?.[0] ?? 0;
  const fp = cm?.[0]?.[1] ?? 0;
  const fn = cm?.[1]?.[0] ?? 0;
  const tp = cm?.[1]?.[1] ?? 0;
  const cmTotal = tn + fp + fn + tp;

  const trainedDate = data?.info.trainedAt
    ? new Date(data.info.trainedAt).toLocaleString(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      })
    : "—";

  const drift = data?.live.drift;

  return (
    <div className="view-stack">
      {offline ? (
        <div className="status-banner status-banner-error" role="alert">
          <AlertTriangle size={16} aria-hidden="true" />
          <p>
            <strong>Offline demo fallback.</strong>{" "}
            <span>
              Showing bundled model evaluation metrics. Live ledger telemetry is unavailable
              offline.
            </span>
          </p>
        </div>
      ) : query.isError ? (
        <div className="status-banner status-banner-error" role="alert">
          <AlertTriangle size={16} aria-hidden="true" />
          <p>
            <strong>Could not load model health.</strong>{" "}
            <span>
              {query.error instanceof Error ? query.error.message : "GET /api/model/health failed."}
            </span>
          </p>
          <Button
            variant="ghost"
            className="action-button"
            type="button"
            onClick={() => void query.refetch()}
          >
            <RefreshCw size={14} aria-hidden="true" /> Retry
          </Button>
        </div>
      ) : null}

      {/* Model metadata cards */}
      <section className="metrics-grid model-meta-grid" aria-label="Deployed model metadata">
        <MetricCard
          loading={loading}
          label="Model version"
          value={data?.info.modelVersion ?? "—"}
          note={
            data
              ? `${data.info.selectedModel} · ${data.info.features.length} features`
              : "Deployed classifier"
          }
          icon={BrainCircuit}
          accent="cyan"
        />
        <MetricCard
          loading={loading}
          label="Trained at"
          value={trainedDate}
          note={data?.info.evaluation ? `Eval: ${data.info.evaluation}` : "Evaluation split"}
          icon={Activity}
          accent="violet"
        />
        <MetricCard
          loading={loading}
          label="Training dataset"
          value={data ? (data.datasetKind === "synthetic" ? "Synthetic" : "Real") : "—"}
          note={
            data
              ? `${data.dataset}${data.trainRows ? ` · ${data.trainRows.toLocaleString()} train / ${(data.testRows ?? 0).toLocaleString()} test` : ""}`
              : "Dataset provenance"
          }
          icon={Database}
          accent="green"
        />
        <MetricCard
          loading={loading}
          label="Artifact size"
          value={formatBytes(data?.artifactBytes ?? null)}
          note={
            data?.webArtifactBytes
              ? `Web inference bundle: ${formatBytes(data.webArtifactBytes)}`
              : "Serialized Random Forest"
          }
          icon={HardDrive}
          accent="coral"
        />
      </section>

      {/* Live ledger stats + drift warning */}
      <section className="panel model-live-panel" aria-labelledby="live-stats-heading">
        <div className="panel-heading">
          <div>
            <h2 id="live-stats-heading">Live inference stats</h2>
            <p>Measured directly from today&apos;s scored traffic and the audit ledger</p>
          </div>
          {drift ? (
            <span className={`drift-pill drift-${drift.status}`} role="status">
              {drift.status === "warning" ? (
                <AlertTriangle size={13} aria-hidden="true" />
              ) : drift.status === "ok" ? (
                <CheckCircle2 size={13} aria-hidden="true" />
              ) : (
                <Info size={13} aria-hidden="true" />
              )}
              <span>
                {drift.status === "warning"
                  ? "Drift warning"
                  : drift.status === "ok"
                    ? "Stable attack rate"
                    : "Baseline building"}
              </span>
            </span>
          ) : null}
        </div>

        <div className="live-stats-grid">
          <div className="live-stat-cell">
            <span>Predictions today</span>
            <strong className="tabular-nums">
              {loading ? "…" : (data?.live.predictionsToday ?? 0).toLocaleString()}
            </strong>
            <small className="tabular-nums">
              {(data?.live.attacksToday ?? 0).toLocaleString()} flagged as attacks
            </small>
          </div>
          <div className="live-stat-cell">
            <span>Attack rate today</span>
            <strong className="tabular-nums">
              {loading
                ? "…"
                : data?.live.attackRateToday != null
                  ? `${data.live.attackRateToday.toFixed(1)}%`
                  : "—"}
            </strong>
            <small>Share of today&apos;s traffic scored ≥ 50%</small>
          </div>
          <div className="live-stat-cell">
            <span>Avg. attack confidence</span>
            <strong className="tabular-nums">
              {loading
                ? "…"
                : data?.live.avgAttackConfidence != null
                  ? `${data.live.avgAttackConfidence.toFixed(1)}%`
                  : "—"}
            </strong>
            <small>Mean probability on detected attacks</small>
          </div>
          <div className="live-stat-cell">
            <span>Drift monitor</span>
            <strong className="tabular-nums">
              {loading
                ? "…"
                : drift?.recentRate != null && drift?.baselineRate != null
                  ? `${drift.recentRate.toFixed(1)}% vs ${drift.baselineRate.toFixed(1)}%`
                  : "Monitoring"}
            </strong>
            <small>{drift?.message ?? "Comparing last hour against prior 24 hours."}</small>
          </div>
        </div>

        {drift?.status === "warning" ? (
          <div className="status-banner status-banner-warn mt-4" role="alert">
            <ShieldAlert size={16} aria-hidden="true" />
            <p>
              <strong>Attack-rate drift detected.</strong> <span>{drift.message}</span>
            </p>
          </div>
        ) : null}
      </section>

      {/* 3-Model Comparison + Confusion Matrix */}
      <section className="model-charts-grid" aria-label="Model evaluation benchmarks">
        <article className="panel traffic-panel">
          <div className="panel-heading">
            <div>
              <h2>Model comparison (RF · LR · NB)</h2>
              <p>Accuracy, precision, recall, and F1 score (%) on the holdout test set</p>
            </div>
            <span className="panel-icon">
              <Gauge size={16} aria-hidden="true" />
            </span>
          </div>

          {loading ? (
            <span className="skeleton-line chart-skeleton" aria-label="Loading comparison chart" />
          ) : comparisonData.length === 0 ? (
            <div className="empty-chart">No model comparison metrics available.</div>
          ) : (
            <>
              <ChartContainer config={comparisonConfig} className="model-bar-chart">
                <BarChart
                  data={comparisonData}
                  margin={{ top: 14, right: 12, left: -12, bottom: 4 }}
                >
                  <CartesianGrid vertical={false} stroke="var(--border)" strokeDasharray="3 5" />
                  <XAxis
                    dataKey="model"
                    axisLine={false}
                    tickLine={false}
                    tick={{ fill: "var(--muted-foreground)", fontSize: 11 }}
                  />
                  <YAxis
                    domain={[80, 100]}
                    axisLine={false}
                    tickLine={false}
                    tickFormatter={(v) => `${v}%`}
                    tick={{ fill: "var(--muted-foreground)", fontSize: 11 }}
                  />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Bar
                    dataKey="accuracy"
                    fill="var(--color-accuracy)"
                    radius={[4, 4, 0, 0]}
                    isAnimationActive={false}
                  />
                  <Bar
                    dataKey="precision"
                    fill="var(--color-precision)"
                    radius={[4, 4, 0, 0]}
                    isAnimationActive={false}
                  />
                  <Bar
                    dataKey="recall"
                    fill="var(--color-recall)"
                    radius={[4, 4, 0, 0]}
                    isAnimationActive={false}
                  />
                  <Bar
                    dataKey="f1"
                    fill="var(--color-f1)"
                    radius={[4, 4, 0, 0]}
                    isAnimationActive={false}
                  />
                </BarChart>
              </ChartContainer>
              <div className="table-scroll mt-3">
                <table className="compact-metrics-table">
                  <thead>
                    <tr>
                      <th scope="col">Model</th>
                      <th scope="col" className="text-right">
                        Accuracy
                      </th>
                      <th scope="col" className="text-right">
                        Precision
                      </th>
                      <th scope="col" className="text-right">
                        Recall
                      </th>
                      <th scope="col" className="text-right">
                        F1
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {comparisonData.map((row) => (
                      <tr key={row.fullName}>
                        <td>
                          {row.fullName}
                          {row.fullName === data?.info.selectedModel ? (
                            <span className="deployed-note"> · Deployed</span>
                          ) : null}
                        </td>
                        <td className="text-right font-mono tabular-nums">
                          {row.accuracy.toFixed(2)}%
                        </td>
                        <td className="text-right font-mono tabular-nums">
                          {row.precision.toFixed(2)}%
                        </td>
                        <td className="text-right font-mono tabular-nums">
                          {row.recall.toFixed(2)}%
                        </td>
                        <td className="text-right font-mono tabular-nums">{row.f1.toFixed(2)}%</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </article>

        <article className="panel traffic-panel">
          <div className="panel-heading">
            <div>
              <h2>Confusion matrix</h2>
              <p>
                {data?.info.selectedModel ?? "Random Forest"} evaluated on{" "}
                {cmTotal.toLocaleString()} test rows
              </p>
            </div>
          </div>

          {loading ? (
            <span className="skeleton-line chart-skeleton" aria-label="Loading confusion matrix" />
          ) : !cm ? (
            <div className="empty-chart">No confusion matrix available.</div>
          ) : (
            <div className="cm-wrapper">
              <div className="cm-grid" role="table" aria-label="Confusion matrix">
                <div className="cm-corner" role="columnheader" />
                <div className="cm-col-head" role="columnheader">
                  Predicted Normal
                </div>
                <div className="cm-col-head" role="columnheader">
                  Predicted Attack
                </div>

                <div className="cm-row-head" role="rowheader">
                  Actual Normal
                </div>
                <div className="cm-cell cm-cell-good" role="cell">
                  <span className="cm-tag">True Negative</span>
                  <strong className="tabular-nums">{tn.toLocaleString()}</strong>
                  <small className="tabular-nums">
                    {cmTotal ? `${((tn / cmTotal) * 100).toFixed(1)}%` : "0%"}
                  </small>
                </div>
                <div className="cm-cell cm-cell-warn" role="cell">
                  <span className="cm-tag">False Positive</span>
                  <strong className="tabular-nums">{fp.toLocaleString()}</strong>
                  <small className="tabular-nums">
                    {cmTotal ? `${((fp / cmTotal) * 100).toFixed(1)}%` : "0%"}
                  </small>
                </div>

                <div className="cm-row-head" role="rowheader">
                  Actual Attack
                </div>
                <div className="cm-cell cm-cell-bad" role="cell">
                  <span className="cm-tag">False Negative</span>
                  <strong className="tabular-nums">{fn.toLocaleString()}</strong>
                  <small className="tabular-nums">
                    {cmTotal ? `${((fn / cmTotal) * 100).toFixed(1)}%` : "0%"}
                  </small>
                </div>
                <div className="cm-cell cm-cell-good" role="cell">
                  <span className="cm-tag">True Positive</span>
                  <strong className="tabular-nums">{tp.toLocaleString()}</strong>
                  <small className="tabular-nums">
                    {cmTotal ? `${((tp / cmTotal) * 100).toFixed(1)}%` : "0%"}
                  </small>
                </div>
              </div>
              <p className="cm-footnote">
                False positive rate:{" "}
                <strong className="font-mono tabular-nums">
                  {tn + fp > 0 ? `${((fp / (tn + fp)) * 100).toFixed(2)}%` : "—"}
                </strong>{" "}
                · Missed attack rate:{" "}
                <strong className="font-mono tabular-nums">
                  {tp + fn > 0 ? `${((fn / (tp + fn)) * 100).toFixed(2)}%` : "—"}
                </strong>
              </p>
            </div>
          )}
        </article>
      </section>

      {/* Top 10 Feature Importances */}
      <section className="panel traffic-panel" aria-labelledby="importances-heading">
        <div className="panel-heading">
          <div>
            <h2 id="importances-heading">Top 10 feature importances</h2>
            <p>Random Forest Gini importance share (%) across network flow features</p>
          </div>
        </div>

        {loading ? (
          <span className="skeleton-line chart-skeleton" aria-label="Loading feature importances" />
        ) : importanceData.length === 0 ? (
          <div className="empty-chart">No feature importances reported in model metrics.</div>
        ) : (
          <ChartContainer config={importanceConfig} className="importance-chart">
            <BarChart
              data={importanceData}
              layout="vertical"
              margin={{ top: 8, right: 24, left: 16, bottom: 8 }}
            >
              <CartesianGrid horizontal={false} stroke="var(--border)" strokeDasharray="3 5" />
              <XAxis
                type="number"
                axisLine={false}
                tickLine={false}
                tickFormatter={(v) => `${v}%`}
                tick={{ fill: "var(--muted-foreground)", fontSize: 11 }}
              />
              <YAxis
                type="category"
                dataKey="feature"
                width={76}
                axisLine={false}
                tickLine={false}
                tick={{ fill: "var(--foreground)", fontSize: 11, fontFamily: "var(--font-mono)" }}
              />
              <ChartTooltip content={<ChartTooltipContent />} />
              <Bar
                dataKey="importancePct"
                fill="var(--color-importancePct)"
                radius={[0, 4, 4, 0]}
                isAnimationActive={false}
              />
            </BarChart>
          </ChartContainer>
        )}
      </section>
    </div>
  );
}
