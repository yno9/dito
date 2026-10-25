/**
 * The did:vh log file and its hashes (VH-Log: The VH-Log File, SCID and Entry
 * Hash Generation and Verification). Pure functions; no signatures here.
 */
import type { Proof } from "../../webvh/src/proof.ts";
import { jcsHash } from "./hash.ts";
import { SCID_PLACEHOLDER } from "./did.ts";

export type VhParameters = {
  method?: string; scid?: string; updateKeys?: string[]; nextKeyHashes?: string[];
  witness?: Record<string, unknown>; watchers?: string[]; deactivated?: boolean; ttl?: number;
};

export type VhLogEntry = {
  versionId: string; versionTime: string; parameters: VhParameters; state: Record<string, any>; proof: Proof[];
};

/** An entry before it is signed. */
export type UnsignedEntry = Omit<VhLogEntry, "proof">;

/** Parse a `did.jsonl` body: one JSON object per line. A missing final newline is tolerated; a blank line is not. */
export function parseVhLog(text: string): VhLogEntry[] {
  const lines = text.split("\n");
  if (lines[lines.length - 1] === "") lines.pop();
  if (!lines.length) throw new Error("The DID log is empty.");
  return lines.map((line, index) => {
    let entry: unknown;
    try { entry = JSON.parse(line); } catch { throw new Error(`DID log line ${index + 1} is not valid JSON.`); }
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw new Error(`DID log line ${index + 1} is not an object.`);
    return entry as VhLogEntry;
  });
}

/** The `did.jsonl` form: compact JSON, one line per entry, newline-terminated. */
export function serializeVhLog(log: ReadonlyArray<VhLogEntry>): string {
  return `${log.map(entry => JSON.stringify(entry)).join("\n")}\n`;
}

/** `<number>-<entry hash>`: the number is positive, canonical, and followed by exactly one dash. */
export function parseVersionId(versionId: unknown): { number: number; hash: string } {
  const match = typeof versionId === "string" ? /^([1-9]\d*)-([1-9A-HJ-NP-Za-km-z]+)$/.exec(versionId) : null;
  if (!match) throw new Error(`Invalid versionId ${JSON.stringify(versionId)}.`);
  return { number: Number(match[1]), hash: match[2]! };
}

/**
 * The entry hash of an entry without its proof. `predecessor` is the SCID for
 * the first entry and the previous entry's whole versionId otherwise: it takes
 * the place of the entry's own versionId in the hashed text.
 */
export function entryHash(entry: UnsignedEntry, predecessor: string): string {
  return jcsHash({ versionId: predecessor, versionTime: entry.versionTime, parameters: entry.parameters, state: entry.state });
}

/**
 * The SCID of a first entry (without a proof) written with the `{SCID}`
 * placeholder everywhere the SCID appears, `versionId` included.
 */
export function generateScid(preliminary: unknown): string {
  return jcsHash(preliminary);
}

/**
 * Whether the first entry's `parameters.scid` is the hash of the entry with
 * every occurrence of the SCID (as text, so also inside the state) put back to
 * the placeholder and `versionId` set to the placeholder.
 */
export function verifyScid(first: VhLogEntry): boolean {
  const scid = first.parameters?.scid;
  if (typeof scid !== "string" || !scid) return false;
  const { proof: _proof, ...rest } = first;
  const text = JSON.stringify({ ...rest, versionId: SCID_PLACEHOLDER }).split(scid).join(SCID_PLACEHOLDER);
  try { return generateScid(JSON.parse(text)) === scid; } catch { return false; }
}

/** A `versionTime` is UTC (`Z` or `+00:00`) in whole seconds. Returns the instant in ms. */
export function parseVersionTime(value: unknown): number {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|\+00:00)$/.test(value)) {
    throw new Error(`Invalid versionTime ${JSON.stringify(value)}: it must be UTC, in whole seconds.`);
  }
  const instant = Date.parse(value);
  if (Number.isNaN(instant)) throw new Error(`Invalid versionTime ${JSON.stringify(value)}.`);
  return instant;
}

/** Now, in whole seconds, as an ISO 8601 UTC string (`2025-04-01T17:39:50Z`). */
export function timestamp(ms: number = Date.now()): string {
  return `${new Date(ms).toISOString().slice(0, 19)}Z`;
}
