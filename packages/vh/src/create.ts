/**
 * Creating, updating and deactivating a did:vh log (VH-Log: Create, Update,
 * Deactivate). Every function returns a log only after verifying the whole of
 * it with the resolver, so a log that comes out of here is one that resolves.
 */
import { createDataIntegrityProof } from "../../webvh/src/proof.ts";
import type { Ed25519Key } from "../../webvh/src/signer.ts";
import { SCID_PLACEHOLDER, VH_METHOD, vhDid } from "./did.ts";
import { entryHash, generateScid, parseVersionId, parseVersionTime, timestamp, type UnsignedEntry, type VhLogEntry, type VhParameters } from "./log.ts";
import { resolveVhLog, type ActiveParameters, applyParameters } from "./verify.ts";

async function sign(entry: UnsignedEntry, signer: Ed25519Key): Promise<VhLogEntry> {
  const proof = await createDataIntegrityProof(entry, {
    privateKey: signer.privateKey, verificationMethod: `did:key:${signer.multikey}#${signer.multikey}`,
    proofPurpose: "assertionMethod", created: entry.versionTime,
  });
  return { ...entry, proof: [proof] };
}

export type CreateVhOptions = {
  /** Signs the first entry; must be one of `updateKeys`. */
  signer: Ed25519Key;
  updateKeys: string[];
  /** Hashes of the keys that may sign the next entry (see keyHash). Non-empty turns pre-rotation on. */
  nextKeyHashes?: string[];
  /** The first DID Document, built for the DID string it is given (`did:vh:{SCID}` while the SCID is unknown). */
  document: (did: string) => Record<string, any>;
  watchers?: string[]; ttl?: number;
  /** ms since the epoch; defaults to now. */
  now?: number;
};

/** Create a log: the first entry, with its SCID, entry hash and proof. */
export async function createVhLog(options: CreateVhOptions): Promise<{ did: string; log: VhLogEntry[] }> {
  const parameters: VhParameters = {
    method: VH_METHOD, scid: SCID_PLACEHOLDER, updateKeys: options.updateKeys,
    ...(options.nextKeyHashes?.length ? { nextKeyHashes: options.nextKeyHashes } : {}),
    ...(options.watchers ? { watchers: options.watchers } : {}),
    ...(options.ttl !== undefined ? { ttl: options.ttl } : {}),
  };
  const placeholderDid = vhDid(SCID_PLACEHOLDER);
  const state = options.document(placeholderDid);
  if (state.id !== placeholderDid) throw new Error(`The first document's id must be ${placeholderDid}.`);
  const versionTime = timestamp(options.now);
  const scid = generateScid({ versionId: SCID_PLACEHOLDER, versionTime, parameters, state });
  const settled = JSON.parse(JSON.stringify({ parameters, state }).split(SCID_PLACEHOLDER).join(scid)) as { parameters: VhParameters; state: Record<string, any> };
  const unsigned: UnsignedEntry = { versionId: scid, versionTime, parameters: settled.parameters, state: settled.state };
  const versionId = `1-${entryHash(unsigned, scid)}`;
  const log = [await sign({ ...unsigned, versionId }, options.signer)];
  const did = vhDid(scid);
  await resolveVhLog(did, log, { now: options.now });
  return { did, log };
}

export type UpdateVhOptions = {
  log: ReadonlyArray<VhLogEntry>;
  signer: Ed25519Key;
  /** The new DID Document. Omit to keep the current one. Its id must stay the DID. */
  document?: Record<string, any>;
  /**
   * Parameters to write into the new entry: only what changes. With pre-rotation
   * active, restate `updateKeys` (keys the previous entry committed to) and `nextKeyHashes`.
   */
  parameters?: VhParameters;
  /** ms since the epoch; defaults to now (but always later than the entry before). */
  now?: number;
};

/** Append one entry to a log and return the whole, verified log. */
export async function updateVhLog(options: UpdateVhOptions): Promise<{ did: string; log: VhLogEntry[] }> {
  const last = options.log[options.log.length - 1];
  if (!last) throw new Error("The log is empty.");
  const did = last.state.id as string;
  const { number } = parseVersionId(last.versionId);
  const time = Math.max(options.now ?? Date.now(), parseVersionTime(last.versionTime) + 1000);
  const unsigned: UnsignedEntry = {
    versionId: last.versionId, versionTime: timestamp(time), parameters: structuredClone(options.parameters ?? {}), state: structuredClone(options.document ?? last.state),
  };
  const versionId = `${number + 1}-${entryHash(unsigned, last.versionId)}`;
  const log = [...options.log, await sign({ ...unsigned, versionId }, options.signer)];
  await resolveVhLog(did, log, { now: Math.max(time, options.now ?? 0) });
  return { did, log };
}

/**
 * Deactivate the DID: a last entry with `deactivated: true`. Under pre-rotation
 * the entry must still restate `updateKeys` and `nextKeyHashes`; this signs with
 * `signer` as the only key and ends the commitment (`nextKeyHashes: []`).
 */
export async function deactivateVhLog(options: { log: ReadonlyArray<VhLogEntry>; signer: Ed25519Key; now?: number }): Promise<{ did: string; log: VhLogEntry[] }> {
  let active: ActiveParameters | undefined;
  options.log.forEach((entry, index) => { active = applyParameters(active, entry.parameters, index === 0); });
  const parameters: VhParameters = active?.nextKeyHashes.length
    ? { deactivated: true, updateKeys: [options.signer.multikey], nextKeyHashes: [] }
    : { deactivated: true };
  return updateVhLog({ log: options.log, signer: options.signer, parameters, now: options.now });
}
