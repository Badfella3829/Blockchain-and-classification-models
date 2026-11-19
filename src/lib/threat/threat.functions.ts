import { createServerFn } from "@tanstack/react-start";
import { getRequestHeader } from "@tanstack/react-start/server";
import { createClient } from "@supabase/supabase-js";
import { z } from "zod";
import type { Database } from "@/integrations/supabase/types";
import { INCIDENT_SORTS, SEVERITIES } from "./types";

function hasSupabaseConfig(): boolean {
  return Boolean(
    process.env["SUPABASE_URL"] &&
    process.env["SUPABASE_PUBLISHABLE_KEY"] &&
    process.env["SUPABASE_SERVICE_ROLE_KEY"],
  );
}

// Public, read-only client (publishable key + read-only policies). Created per request.
function publicClient() {
  const url = process.env["SUPABASE_URL"];
  const key = process.env["SUPABASE_PUBLISHABLE_KEY"];
  if (!url || !key) throw new Error("Backend is not configured.");
  return createClient<Database>(url, key, {
    auth: { persistSession: false, autoRefreshToken: false },
    global: {
      fetch: (input, init) => {
        const headers = new Headers(init?.headers);
        if (key.startsWith("sb_") && headers.get("Authorization") === `Bearer ${key}`)
          headers.delete("Authorization");
        headers.set("apikey", key);
        return fetch(input, { ...init, headers });
      },
    },
  });
}

async function adminClient() {
  const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
  return supabaseAdmin;
}

const ledger = () => import("./ledger.server");
const localLedger = () => import("./local-ledger.server");

export const getDashboardMetrics = createServerFn({ method: "GET" }).handler(async () => {
  if (!hasSupabaseConfig()) {
    const { localDashboardMetrics } = await localLedger();
    return localDashboardMetrics();
  }
  const { dashboardMetrics, ensureGenesis } = await ledger();
  const db = publicClient();
  const metrics = await dashboardMetrics(db);
  if (metrics.chainLength === 0) {
    // First request on an empty ledger: create the genesis block once.
    await ensureGenesis(await adminClient());
    return { ...metrics, chainLength: 1 };
  }
  return metrics;
});

const incidentQuery = z.object({
  severity: z.enum(SEVERITIES as [string, ...string[]]).optional(),
  status: z.enum(["Open", "Contained"]).optional(),
  search: z
    .string()
    .max(60)
    .regex(/^[\w .:-]*$/, "Search may only use letters, numbers, spaces, dots, colons and dashes.")
    .optional(),
  sort: z.enum(INCIDENT_SORTS).optional(),
  order: z.enum(["asc", "desc"]).optional(),
  page: z.number().int().min(1).max(10_000).default(1),
  pageSize: z.number().int().min(1).max(1000).default(10),
});

export const getIncidents = createServerFn({ method: "GET" })
  .inputValidator((input: z.input<typeof incidentQuery>) => incidentQuery.parse(input))
  .handler(async ({ data }) => {
    const options = {
      page: data.page,
      pageSize: data.pageSize,
      ...(data.severity ? { severity: data.severity as (typeof SEVERITIES)[number] } : {}),
      ...(data.status ? { status: data.status } : {}),
      ...(data.search ? { search: data.search } : {}),
      ...(data.sort ? { sort: data.sort } : {}),
      ...(data.order ? { order: data.order } : {}),
    };
    if (!hasSupabaseConfig()) {
      const { localListIncidents } = await localLedger();
      return localListIncidents(options);
    }
    const { listIncidents } = await ledger();
    return listIncidents(publicClient(), options);
  });

export const getIncidentDetail = createServerFn({ method: "GET" })
  .inputValidator((input: { id: string }) =>
    z.object({ id: z.string().regex(/^SIG-[A-Z0-9]{4,16}$/) }).parse(input),
  )
  .handler(async ({ data }) => {
    if (!hasSupabaseConfig()) {
      const { localGetIncident } = await localLedger();
      return localGetIncident(data.id);
    }
    const { getIncident } = await ledger();
    return getIncident(publicClient(), data.id);
  });

export const getAlerts = createServerFn({ method: "GET" })
  .inputValidator((input: { since: string | null }) =>
    z.object({ since: z.string().datetime().nullable() }).parse(input),
  )
  .handler(async ({ data }) => {
    if (!hasSupabaseConfig()) {
      const { localAlertsSince } = await localLedger();
      return localAlertsSince(data.since);
    }
    const { alertsSince } = await ledger();
    return alertsSince(publicClient(), data.since);
  });

export const getBlocks = createServerFn({ method: "GET" })
  .inputValidator((input: { page?: number; pageSize?: number }) =>
    z
      .object({
        page: z.number().int().min(1).max(10_000).default(1),
        pageSize: z.number().int().min(1).max(100).default(15),
      })
      .parse(input),
  )
  .handler(async ({ data }) => {
    if (!hasSupabaseConfig()) {
      const { localListBlocks } = await localLedger();
      return localListBlocks(data.page, data.pageSize);
    }
    const { listBlocks } = await ledger();
    return listBlocks(publicClient(), data.page, data.pageSize);
  });

export const exportChain = createServerFn({ method: "GET" }).handler(async () => {
  if (!hasSupabaseConfig()) {
    const { localAllBlocks } = await localLedger();
    return localAllBlocks();
  }
  const { allBlocks } = await ledger();
  return allBlocks(publicClient());
});

export const getModelHealth = createServerFn({ method: "GET" }).handler(async () => {
  if (!hasSupabaseConfig()) {
    const { localModelHealth } = await localLedger();
    return localModelHealth();
  }
  const { modelHealth } = await ledger();
  return modelHealth(publicClient());
});

export const updateIncidentStatus = createServerFn({ method: "POST" })
  .inputValidator((input: { id: string; status: "Open" | "Contained"; by: string }) =>
    z
      .object({
        id: z.string().regex(/^SIG-[A-Z0-9]{4,16}$/),
        status: z.enum(["Open", "Contained"]),
        by: z.string().trim().min(1).max(40),
      })
      .parse(input),
  )
  .handler(async ({ data }) => {
    if (!hasSupabaseConfig()) {
      const { localChangeIncidentStatus } = await localLedger();
      return localChangeIncidentStatus(data.id, data.status, data.by);
    }
    const { changeIncidentStatus } = await ledger();
    return changeIncidentStatus(await adminClient(), data.id, data.status, data.by);
  });

export const getRecentBlocks = createServerFn({ method: "GET" })
  .inputValidator((input: { limit?: number }) =>
    z.object({ limit: z.number().int().min(1).max(50).default(6) }).parse(input),
  )
  .handler(async ({ data }) => {
    if (!hasSupabaseConfig()) {
      const { localRecentBlocks } = await localLedger();
      return localRecentBlocks(data.limit);
    }
    const { recentBlocks } = await ledger();
    return recentBlocks(publicClient(), data.limit);
  });

export const verifyChain = createServerFn({ method: "GET" }).handler(async () => {
  if (!hasSupabaseConfig()) {
    const { localVerifyLedger } = await localLedger();
    return localVerifyLedger();
  }
  const { verifyLedger } = await ledger();
  return verifyLedger(publicClient());
});

function clientKeySource() {
  const forwarded =
    getRequestHeader("cf-connecting-ip") ?? getRequestHeader("x-forwarded-for")?.split(",")[0];
  return (forwarded ?? "unknown").trim();
}

async function hashedClientKey() {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(`sentinel:${clientKeySource()}`),
  );
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

export const runSimulation = createServerFn({ method: "POST" })
  .inputValidator((input: { count?: number }) =>
    z.object({ count: z.number().int().min(1).max(20).default(10) }).parse(input),
  )
  .handler(async ({ data }) => {
    if (!hasSupabaseConfig()) {
      const { localRunSimulation } = await localLedger();
      return localRunSimulation(await hashedClientKey(), data.count);
    }
    const ledgerModule = await ledger();
    return ledgerModule.runSimulation(await adminClient(), await hashedClientKey(), data.count);
  });

const featureValue = z.union([z.number().finite(), z.string().max(64), z.null()]);

export const predictRecord = createServerFn({ method: "POST" })
  .inputValidator(
    (input: {
      features: Record<string, number | string | null>;
      source?: string;
      category?: string;
    }) =>
      z
        .object({
          features: z
            .record(featureValue)
            .refine(
              (f) => Object.keys(f).length > 0 && Object.keys(f).length <= 60,
              "Provide 1-60 features.",
            ),
          source: z.string().max(64).optional(),
          category: z.string().max(64).optional(),
        })
        .parse(input),
  )
  .handler(async ({ data }) => {
    const meta = {
      ...(data.source ? { source: data.source } : {}),
      ...(data.category ? { category: data.category } : {}),
    };
    if (!hasSupabaseConfig()) {
      const { localPredictAndRecord, localScoreRecord } = await localLedger();
      localScoreRecord(data.features);
      return localPredictAndRecord(data.features, meta);
    }
    const { predictAndRecord, scoreRecord } = await ledger();
    scoreRecord(data.features); // validates feature names before any write
    return predictAndRecord(await adminClient(), data.features, meta);
  });
