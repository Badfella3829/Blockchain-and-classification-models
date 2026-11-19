import { createContext, createElement, useContext, useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { toast } from "sonner";
import { api, metricsQuery } from "@/lib/api";
import type { ChainVerification, IncidentStatus } from "@/lib/threat/types";
import { usePreferences } from "./use-preferences";

const errorText = (error: unknown) => (error instanceof Error ? error.message : String(error));

/** Live metrics; `offline` means the API was never reachable this visit. */
export function useLiveMetrics() {
  const { refetchInterval } = usePreferences();
  const metrics = useQuery(metricsQuery(refetchInterval));
  return { metrics, offline: metrics.isError && !metrics.data };
}

export function useSimulation() {
  const queryClient = useQueryClient();
  const simulate = useServerFn(api.runSimulation);
  return useMutation({
    mutationFn: (count: number) => simulate({ data: { count } }),
    onSuccess: (result) => {
      if (!result.ok) {
        toast.error(result.status === 429 ? "Slow down" : "Simulation unavailable", { description: result.message });
        return;
      }
      toast.success(`Simulated ${result.processed} events`, {
        description: `${result.attacks} attacks recorded on the ledger, ${result.normal} normal.${result.capped ? " Ledger limit reached." : ""}`,
      });
      void queryClient.invalidateQueries({ queryKey: ["threat"] });
    },
    onError: (error) => toast.error("Simulation failed", { description: errorText(error) }),
  });
}

export function useStatusChange() {
  const queryClient = useQueryClient();
  const update = useServerFn(api.updateIncidentStatus);
  return useMutation({
    mutationFn: (input: { id: string; status: IncidentStatus; by: string }) => update({ data: input }),
    onSuccess: (result, input) => {
      if (!result.ok) {
        toast.error("Status not changed", { description: result.message });
        return;
      }
      toast.success(`${input.id} marked ${result.status}`, { description: `Recorded in ledger block #${result.blockIndex}.` });
      void queryClient.invalidateQueries({ queryKey: ["threat"] });
    },
    onError: (error) => toast.error("Status change failed", { description: errorText(error) }),
  });
}

type IntegrityState = {
  result: ChainVerification | null;
  isPending: boolean;
  verify: () => void;
};

const IntegrityContext = createContext<IntegrityState | null>(null);

/** Shares the last ledger verification across views. */
export function IntegrityProvider({ children }: { children: ReactNode }) {
  const verifyFn = useServerFn(api.verifyChain);
  const [result, setResult] = useState<ChainVerification | null>(null);
  const mutation = useMutation({
    mutationFn: () => verifyFn(),
    onSuccess: (data) => {
      setResult(data);
      if (data.valid) toast.success("Ledger integrity verified", { description: `All ${data.length} blocks are intact.` });
      else toast.error(`Tampering detected at block #${data.badIndex}`, { description: data.reason ?? undefined });
    },
    onError: (error) => toast.error("Verification failed", { description: errorText(error) }),
  });
  const value: IntegrityState = { result, isPending: mutation.isPending, verify: () => mutation.mutate() };
  return createElement(IntegrityContext.Provider, { value }, children);
}

export function useIntegrity() {
  const value = useContext(IntegrityContext);
  if (!value) throw new Error("useIntegrity must be used inside IntegrityProvider");
  return value;
}
