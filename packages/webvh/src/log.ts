/**
 * Thin, opinionated wrappers over didwebvh-ts: the only place the rest of the
 * code touches the library, so its (fast-moving) API stays contained here.
 */
import {
  createDID,
  deactivateDID,
  deriveNextKeyHash,
  resolveDIDFromLog,
  updateDID,
  type DIDDoc,
  type DIDLog,
  type DIDLogEntry,
  type DIDResolutionMeta,
  type Signer,
  type Verifier,
} from "didwebvh-ts";
import { ed25519Verifier } from "./signer.ts";

export type { DIDDoc, DIDLog, DIDLogEntry, DIDResolutionMeta, Signer, Verifier };

/** The multihash a `nextKeyHashes` entry commits to for a next update key. */
export const nextKeyHash = deriveNextKeyHash;

/** Parse a `did.jsonl` body: one JSON entry per line, newline-terminated. */
export function parseLog(text: string): DIDLog {
  if (!text.endsWith("\n")) throw new Error("A DID log must end with a newline.");
  return text.trimEnd().split("\n").map((line, index) => {
    try { return JSON.parse(line) as DIDLogEntry; }
    catch { throw new Error(`DID log line ${index + 1} is not valid JSON.`); }
  });
}

/** Serialise a log to its `did.jsonl` form. */
export function serializeLog(log: DIDLog): string {
  return `${log.map(entry => JSON.stringify(entry)).join("\n")}\n`;
}

/** Parameters in force after the last entry (later entries override earlier). */
export function currentParameters(log: DIDLog): DIDLogEntry["parameters"] {
  return log.reduce<DIDLogEntry["parameters"]>((active, entry) => ({ ...active, ...entry.parameters }), {});
}

export type CreateLogOptions = Parameters<typeof createDID>[0];
export type UpdateLogOptions = Parameters<typeof updateDID>[0];

/** Create a portable did:webvh log. `verifier` defaults to Ed25519. */
export function createLog(options: CreateLogOptions) {
  return createDID({ portable: true, verifier: ed25519Verifier, ...options });
}

/** Append one signed entry (rotation, document change, or a `domain` move). */
export function updateLog(options: UpdateLogOptions & { domain?: string; services?: DIDDoc["service"] }) {
  return updateDID({ verifier: ed25519Verifier, ...options } as Parameters<typeof updateDID>[0]);
}

/** Permanently deactivate the DID. */
export function deactivateLog(options: Parameters<typeof deactivateDID>[0]) {
  return deactivateDID({ verifier: ed25519Verifier, ...options });
}

/**
 * Validate a whole log and resolve its latest DID Document. Throws if invalid.
 *
 * didwebvh-ts 2.8.0 accepts an entry whose `proof` is an empty array (an
 * unsigned entry passes; only a *missing* `proof` key is rejected), so that
 * gap is closed here for every caller.
 */
export function resolveLog(log: DIDLog, options: Parameters<typeof resolveDIDFromLog>[1] = {}) {
  for (const [index, entry] of log.entries()) {
    if (!Array.isArray(entry.proof) || entry.proof.length === 0) {
      return Promise.reject(new Error(`Missing proof in DID log entry ${index + 1}`));
    }
  }
  return resolveDIDFromLog(log, { verifier: ed25519Verifier, ...options });
}
