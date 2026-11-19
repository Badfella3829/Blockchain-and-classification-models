// Server-side HTTP API routes (/api/model/health, /api/incidents/:id/status, /api/readme).
import { createClient } from "@supabase/supabase-js";
import { z } from "zod";
import type { Database } from "@/integrations/supabase/types";
import readmeText from "../../../README.md?raw";

function hasSupabaseConfig(): boolean {
  return Boolean(
    process.env["SUPABASE_URL"] &&
    process.env["SUPABASE_PUBLISHABLE_KEY"] &&
    process.env["SUPABASE_SERVICE_ROLE_KEY"],
  );
}

function publicClient() {
  const url = process.env["SUPABASE_URL"]!;
  const key = process.env["SUPABASE_PUBLISHABLE_KEY"]!;
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

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

const statusPayloadSchema = z.object({
  status: z.enum(["Open", "Contained"]).optional(),
  new_status: z.enum(["Open", "Contained"]).optional(),
  by: z.string().trim().min(1).max(40).default("Security team"),
});

const incidentIdSchema = z.string().regex(/^SIG-[A-Z0-9]{4,16}$/, "Invalid incident ID.");

const predictPayloadSchema = z.object({
  features: z.record(z.union([z.number(), z.string(), z.null()])),
  source: z.string().trim().max(48).optional(),
  category: z.string().trim().max(48).optional(),
  recordToLedger: z.boolean().default(false),
});

export async function handleThreatApiRequest(request: Request): Promise<Response | null> {
  const url = new URL(request.url);
  const pathname = url.pathname;

  // GET /api/model/health
  if (pathname === "/api/model/health" && request.method === "GET") {
    try {
      if (hasSupabaseConfig()) {
        const { modelHealth } = await import("./ledger.server");
        return jsonResponse(await modelHealth(publicClient()));
      }
      const { localModelHealth } = await import("./local-ledger.server");
      return jsonResponse(await localModelHealth());
    } catch (error) {
      return jsonResponse(
        { error: error instanceof Error ? error.message : "Could not read model health." },
        500,
      );
    }
  }

  // POST /api/incidents/{id}/status
  const statusMatch = /^\/api\/incidents\/([^/]+)\/status$/.exec(pathname);
  if (statusMatch && request.method === "POST") {
    const rawId = decodeURIComponent(statusMatch[1] ?? "");
    const idCheck = incidentIdSchema.safeParse(rawId);
    if (!idCheck.success) {
      return jsonResponse({ ok: false, message: "Invalid incident ID format." }, 400);
    }

    let rawBody: unknown;
    try {
      rawBody = await request.json();
    } catch {
      return jsonResponse({ ok: false, message: "Request body must be valid JSON." }, 400);
    }

    const parsed = statusPayloadSchema.safeParse(rawBody);
    const nextStatus = parsed.success ? (parsed.data.status ?? parsed.data.new_status) : undefined;
    if (!parsed.success || !nextStatus) {
      return jsonResponse({ ok: false, message: "Provide status: 'Open' or 'Contained'." }, 400);
    }

    try {
      const result = hasSupabaseConfig()
        ? await (
            await import("./ledger.server")
          ).changeIncidentStatus(await adminClient(), idCheck.data, nextStatus, parsed.data.by)
        : await (
            await import("./local-ledger.server")
          ).localChangeIncidentStatus(idCheck.data, nextStatus, parsed.data.by);
      if (!result.ok) {
        const statusCode = result.message.includes("not found")
          ? 404
          : result.message.includes("full")
            ? 429
            : 409;
        return jsonResponse(result, statusCode);
      }
      return jsonResponse(result, 200);
    } catch (error) {
      return jsonResponse(
        {
          ok: false,
          message: error instanceof Error ? error.message : "Could not record status change.",
        },
        500,
      );
    }
  }

  // POST /api/predict — score a custom network flow with the deployed Random Forest.
  if (pathname === "/api/predict" && request.method === "POST") {
    let rawBody: unknown;
    try {
      rawBody = await request.json();
    } catch {
      return jsonResponse({ ok: false, message: "Request body must be valid JSON." }, 400);
    }
    const parsed = predictPayloadSchema.safeParse(rawBody);
    if (!parsed.success) {
      return jsonResponse({ ok: false, message: "Invalid flow features payload." }, 400);
    }
    try {
      const { localAnalyzeFlow } = await import("./local-ledger.server");
      const result = await localAnalyzeFlow(parsed.data);
      return jsonResponse(result, 200);
    } catch (error) {
      return jsonResponse(
        { ok: false, message: error instanceof Error ? error.message : "Flow analysis failed." },
        400,
      );
    }
  }

  // GET /api/readme — serves repository README for the Help dialog link.
  if (pathname === "/api/readme" && request.method === "GET") {
    return new Response(readmeText, {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  return null;
}
