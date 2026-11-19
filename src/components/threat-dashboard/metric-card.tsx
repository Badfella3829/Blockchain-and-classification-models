import { ArrowDownRight, ArrowUpRight, type LucideIcon } from "lucide-react";

type MetricCardProps = {
  label: string;
  value: string;
  note: string;
  trend?: string;
  trendTone?: "positive" | "negative" | "neutral";
  icon: LucideIcon;
  loading?: boolean;
  accent: "cyan" | "coral" | "violet" | "green";
};

export function MetricCard({
  label,
  value,
  note,
  trend,
  trendTone = "neutral",
  icon: Icon,
  loading = false,
  accent,
}: MetricCardProps) {
  const TrendIcon = trendTone === "negative" ? ArrowDownRight : ArrowUpRight;

  return (
    <article className="metric-card">
      <div className="metric-card-top">
        <span className={`metric-icon metric-icon-${accent}`} aria-hidden="true">
          <Icon size={18} strokeWidth={1.8} />
        </span>
        {trend ? (
          <span className={`metric-trend metric-trend-${trendTone}`}>
            <TrendIcon size={13} aria-hidden="true" />
            {trend}
          </span>
        ) : null}
      </div>
      <p className="metric-label">{label}</p>
      <div className="metric-value-row">
        {loading ? (
          <span className="skeleton-line" style={{ width: 90, height: 30 }} aria-label="Loading" />
        ) : (
          <strong className="metric-value">{value}</strong>
        )}
      </div>
      <p className="metric-note">{note}</p>
    </article>
  );
}
