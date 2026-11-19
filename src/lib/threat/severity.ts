import type { Severity } from "./types";

/** Severity of an attack probability: Critical >=0.95, High >=0.8, Medium >=0.5, else Low. */
export function severityFor(probability: number): Severity {
  if (probability >= 0.95) return "Critical";
  if (probability >= 0.8) return "High";
  if (probability >= 0.5) return "Medium";
  return "Low";
}

export const ATTACK_THRESHOLD = 0.5;
