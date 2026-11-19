/**
 * The one block-hash format shared with the Python code (api/_lib/blockchain.py):
 * keys sorted, compact separators, UTF-8, whole numbers written without ".0".
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Non-finite numbers cannot be hashed.");
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
  }
  throw new Error(`Unsupported value in block: ${typeof value}`);
}

export async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

export type UnhashedBlock = {
  index: number;
  timestamp: string;
  event: unknown;
  previous_hash: string;
};

export function hashBlock(block: UnhashedBlock): Promise<string> {
  return sha256Hex(
    canonicalJson({
      index: block.index,
      timestamp: block.timestamp,
      event: block.event,
      previous_hash: block.previous_hash,
    }),
  );
}

export const GENESIS_EVENT = "Genesis Block";

/** Returns the first invalid block (1-based index) or null when the chain is intact. */
export async function verifyBlocks(
  blocks: {
    index: number;
    timestamp: string;
    event: unknown;
    previous_hash: string;
    hash: string;
  }[],
): Promise<{ valid: boolean; badIndex: number | null; reason: string | null }> {
  if (blocks.length === 0) return { valid: false, badIndex: null, reason: "Chain is empty." };
  let previousHash = "0";
  for (const [i, block] of blocks.entries()) {
    const position = i + 1;
    if (block.index !== position)
      return { valid: false, badIndex: position, reason: "Block index is out of sequence." };
    if (block.previous_hash !== previousHash)
      return {
        valid: false,
        badIndex: position,
        reason: "Previous hash does not match the prior block.",
      };
    if (i === 0 && block.event !== GENESIS_EVENT)
      return { valid: false, badIndex: 1, reason: "Genesis block was modified." };
    const expected = await hashBlock(block);
    if (block.hash !== expected)
      return { valid: false, badIndex: position, reason: "Block content does not match its hash." };
    previousHash = block.hash;
  }
  return { valid: true, badIndex: null, reason: null };
}
