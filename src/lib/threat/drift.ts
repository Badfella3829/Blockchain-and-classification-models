import type { DriftResult } from "./types";

export const DRIFT = { minSamples: 20, thresholdPoints: 20 } as const;

/**
 * Simple drift check: compares the last hour's attack rate with the previous
 * 24 hours. Warns when they differ by more than 20 percentage points and both
 * windows have at least 20 predictions.
 */
export function detectDrift(
  recent: { n: number; attacks: number },
  earlier: { n: number; attacks: number },
): DriftResult {
  const recentRate = recent.n ? (recent.attacks * 100) / recent.n : null;
  const baselineRate = earlier.n ? (earlier.attacks * 100) / earlier.n : null;
  if (
    recent.n < DRIFT.minSamples ||
    earlier.n < DRIFT.minSamples ||
    recentRate === null ||
    baselineRate === null
  ) {
    return {
      status: "insufficient",
      recentRate,
      baselineRate,
      message: `Needs at least ${DRIFT.minSamples} predictions in the last hour and in the 24 hours before it.`,
    };
  }
  const delta = recentRate - baselineRate;
  if (Math.abs(delta) > DRIFT.thresholdPoints) {
    return {
      status: "warning",
      recentRate,
      baselineRate,
      message: `Attack rate ${delta > 0 ? "rose" : "fell"} from ${baselineRate.toFixed(1)}% to ${recentRate.toFixed(1)}% in the last hour.`,
    };
  }
  return {
    status: "ok",
    recentRate,
    baselineRate,
    message: "Attack rate is in line with the earlier average.",
  };
}
