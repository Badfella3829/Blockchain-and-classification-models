import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import { Area, CartesianGrid, ComposedChart, Line, XAxis, YAxis } from "recharts";
import { useId } from "react";

const chartConfig = {
  events: { label: "Events analyzed", color: "var(--chart-1)" },
  threats: { label: "Threat signals", color: "var(--chart-2)" },
} satisfies ChartConfig;

export type TrafficPoint = { time: string; events: number; threats: number };

export function TrafficChart({ data }: { data: TrafficPoint[] }) {
  const maxThreats = Math.max(4, ...data.map((point) => point.threats));
  const gradientId = `event-fill-${useId().replace(/:/g, "")}`;

  return (
    <ChartContainer config={chartConfig} className="traffic-chart">
      <ComposedChart
        accessibilityLayer
        data={data}
        key="sentinel-traffic-chart"
        margin={{ top: 12, right: 8, left: 4, bottom: 0 }}
      >
        <defs>
          <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--color-events)" stopOpacity={0.22} />
            <stop offset="100%" stopColor="var(--color-events)" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid vertical={false} stroke="var(--border)" strokeDasharray="3 5" />
        <XAxis
          dataKey="time"
          axisLine={false}
          tickLine={false}
          tickMargin={12}
          tick={{ fill: "var(--muted-foreground)", fontSize: 11 }}
        />
        <YAxis
          yAxisId="events"
          axisLine={false}
          tickLine={false}
          tick={{ fill: "var(--muted-foreground)", fontSize: 11 }}
          width={42}
        />
        <YAxis
          yAxisId="threats"
          orientation="right"
          hide
          domain={[0, Math.ceil(maxThreats * 1.25)]}
        />
        <ChartTooltip
          cursor={{ stroke: "var(--border)", strokeDasharray: "4 4" }}
          content={<ChartTooltipContent />}
        />
        <Area
          yAxisId="events"
          type="monotone"
          dataKey="events"
          isAnimationActive={false}
          stroke="var(--color-events)"
          strokeWidth={2}
          fill={`url(#${gradientId})`}
          activeDot={{ r: 4, strokeWidth: 0 }}
        />
        <Line
          yAxisId="threats"
          type="monotone"
          dataKey="threats"
          isAnimationActive={false}
          stroke="var(--color-threats)"
          strokeWidth={2}
          dot={false}
          activeDot={{ r: 4, strokeWidth: 0 }}
        />
      </ComposedChart>
    </ChartContainer>
  );
}
