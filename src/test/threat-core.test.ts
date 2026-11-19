import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { canonicalJson, GENESIS_EVENT, hashBlock, sha256Hex, verifyBlocks } from "@/lib/threat/canonical";
import { severityFor } from "@/lib/threat/severity";
import { predictProbability, type FeatureRecord, type WebModelBundle } from "@/lib/threat/web-model";

const modelDir = resolve(__dirname, "../lib/threat/model");
const bundle = JSON.parse(readFileSync(resolve(modelDir, "web-model.json"), "utf8")) as WebModelBundle;
const rows = JSON.parse(readFileSync(resolve(modelDir, "simulation-rows.json"), "utf8")) as {
  features: FeatureRecord;
  expected_probability: number;
}[];

describe("severity mapping", () => {
  it("uses Critical >=0.95, High >=0.8, Medium >=0.5, else Low", () => {
    expect([0.95, 0.9499, 0.8, 0.7999, 0.5, 0.4999].map(severityFor)).toEqual([
      "Critical",
      "High",
      "High",
      "Medium",
      "Medium",
      "Low",
    ]);
  });
});

describe("block hashing", () => {
  // Same block and expected values as source/model's Python check.
  const block = {
    index: 2,
    timestamp: "2026-11-19T07:48:00.000Z",
    event: {
      type: "detection",
      event_id: "SIG-0A1B2C3D",
      source: "10.1.2.3",
      category: "Exploits",
      severity: "Critical",
      confidence: 97.0,
      model_version: "rf-20261119074700",
      status: "Open",
      note: "नमस्ते",
    },
    previous_hash: "abc",
  };

  it("produces the same canonical text and hash as Python", async () => {
    expect(canonicalJson(block)).toBe(
      '{"event":{"category":"Exploits","confidence":97,"event_id":"SIG-0A1B2C3D","model_version":"rf-20261119074700","note":"नमस्ते","severity":"Critical","source":"10.1.2.3","status":"Open","type":"detection"},"index":2,"previous_hash":"abc","timestamp":"2026-11-19T07:48:00.000Z"}',
    );
    expect(await hashBlock(block)).toBe("19426b6bbfa14ef3d6a336349da69dc0e1d3d2fa696f9c43676cceb4fec842c0");
  });

  it("reports the first tampered block index", async () => {
    const genesis = { index: 1, timestamp: "t0", event: GENESIS_EVENT, previous_hash: "0" };
    const chain: { index: number; timestamp: string; event: unknown; previous_hash: string; hash: string }[] = [
      { ...genesis, hash: await hashBlock(genesis) },
    ];
    for (let i = 2; i <= 4; i += 1) {
      const next = { index: i, timestamp: `t${i}`, event: { n: i }, previous_hash: chain[chain.length - 1]!.hash };
      chain.push({ ...next, hash: await hashBlock(next) });
    }
    expect(await verifyBlocks(chain)).toEqual({ valid: true, badIndex: null, reason: null });
    const tampered = chain.map((b) => ({ ...b }));
    tampered[2] = { ...tampered[2]!, event: { n: 999 } };
    expect((await verifyBlocks(tampered)).badIndex).toBe(3);
    expect((await sha256Hex("abc")).length).toBe(64);
  });
});

describe("web model", () => {
  it("matches the Python model on 5 sample inputs", () => {
    for (const row of rows.slice(0, 5)) {
      expect(predictProbability(bundle, row.features)).toBeCloseTo(row.expected_probability, 9);
    }
  });

  it("matches the Python model on every exported simulation row", () => {
    const mismatches = rows.filter((row) => Math.abs(predictProbability(bundle, row.features) - row.expected_probability) > 1e-9);
    expect(mismatches).toHaveLength(0);
  });
});
