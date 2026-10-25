/**
 * Resolving a did:vh log: the whole log is verified, every entry, in order
 * (VH-Log: Read (Resolve); didvh-spec: Resolution Algorithm and the Resolver
 * Validation Checklist). The resolver never looks for the log; it is handed one.
 *
 * Stricter than the specification where the specification leaves room:
 * - an invalid entry anywhere fails the whole resolution (the spec lets a
 *   resolver return an earlier version "even if later entries are invalid");
 * - every proof in an entry must verify, not just one;
 * - unknown members of an entry or of `parameters` are refused.
 * Witnesses are not implemented yet: a log that configures any is refused
 * (`featureNotSupported`) rather than accepted without the approvals it needs.
 */
import { verifyDataIntegrityProof, publicKeyFromMultikey } from "./proof.ts";
import { checkAndRemember, type VersionMemory } from "./freshness.ts";
import { VH_METHOD, parseVhDid, isScid } from "./did.ts";
import { keyHash } from "./hash.ts";
import { entryHash, parseVersionId, parseVersionTime, verifyScid, type VhLogEntry, type VhParameters } from "./log.ts";

export type VhErrorCode = "invalidDid" | "invalidOptions" | "invalidLog" | "notFound" | "featureNotSupported";

export class VhResolutionError extends Error {
  readonly code: VhErrorCode;
  constructor(code: VhErrorCode, message: string) {
    super(message);
    this.name = "VhResolutionError";
    this.code = code;
  }
}

const invalid = (message: string) => new VhResolutionError("invalidLog", message);

/** The parameters in force after an entry. */
export type ActiveParameters = {
  method: string; updateKeys: string[]; nextKeyHashes: string[]; witness: Record<string, unknown>;
  watchers: string[]; deactivated: boolean; ttl: number;
};

const ENTRY_MEMBERS = ["versionId", "versionTime", "parameters", "state", "proof"];
const PARAMETER_MEMBERS = ["method", "scid", "updateKeys", "nextKeyHashes", "witness", "watchers", "deactivated", "ttl"];
const FUTURE_TOLERANCE_MS = 5 * 60 * 1000;

function stringArray(value: unknown, name: string): string[] {
  if (!Array.isArray(value) || !value.every(item => typeof item === "string" && item)) throw invalid(`parameters.${name} must be an array of strings.`);
  return value;
}

/** Fold an entry's `parameters` into the active ones (VH-Log: Parameters; didvh-spec: Parameters). */
export function applyParameters(previous: ActiveParameters | undefined, parameters: unknown, first: boolean): ActiveParameters {
  if (!parameters || typeof parameters !== "object" || Array.isArray(parameters)) throw invalid("parameters must be an object.");
  const given = parameters as Record<string, unknown>;
  for (const name of Object.keys(given)) {
    if (name === "portable") throw invalid("parameters.portable is not a did:vh parameter.");
    if (name === "logVersion") throw invalid("parameters.logVersion must not be used in a did:vh log; use method.");
    if (!PARAMETER_MEMBERS.includes(name)) throw invalid(`parameters.${name} is not a did:vh parameter.`);
    if (given[name] === null) throw invalid(`parameters.${name} must not be null.`);
  }
  if (first) {
    if (!isScid(given.scid)) throw invalid("The first entry must carry parameters.scid.");
    if (given.method === undefined) throw invalid("The first entry must carry parameters.method.");
    if (given.updateKeys === undefined) throw invalid("The first entry must carry parameters.updateKeys.");
  } else if (given.scid !== undefined) throw invalid("parameters.scid may only appear in the first entry.");

  const method = given.method ?? previous?.method;
  if (method !== VH_METHOD) throw invalid(`Unsupported method ${JSON.stringify(method)}.`);

  const updateKeys = given.updateKeys === undefined ? previous!.updateKeys : stringArray(given.updateKeys, "updateKeys");
  for (const key of updateKeys) if (!publicKeyFromMultikey(key)) throw invalid("parameters.updateKeys must hold Ed25519 multikeys.");
  if (first && !updateKeys.length) throw invalid("The first entry must authorise at least one key.");

  const nextKeyHashes = given.nextKeyHashes === undefined ? previous?.nextKeyHashes ?? [] : stringArray(given.nextKeyHashes, "nextKeyHashes");

  let witness = previous?.witness ?? {};
  if (given.witness !== undefined) {
    if (typeof given.witness !== "object" || Array.isArray(given.witness)) throw invalid("parameters.witness must be an object.");
    witness = given.witness as Record<string, unknown>;
  }
  if (Object.keys(witness).length) throw new VhResolutionError("featureNotSupported", "This log uses witnesses, which this resolver does not support yet.");

  let watchers = previous?.watchers ?? [];
  if (given.watchers !== undefined) {
    watchers = stringArray(given.watchers, "watchers");
    for (const url of watchers) {
      let parsed: URL;
      try { parsed = new URL(url); } catch { throw invalid("parameters.watchers must hold URLs."); }
      if (parsed.protocol !== "https:") throw invalid("parameters.watchers must hold https URLs.");
    }
  }

  let deactivated = previous?.deactivated ?? false;
  if (given.deactivated !== undefined) {
    if (typeof given.deactivated !== "boolean") throw invalid("parameters.deactivated must be a boolean.");
    deactivated = given.deactivated;
  }

  let ttl = previous?.ttl ?? 3600;
  if (given.ttl !== undefined) {
    if (!Number.isInteger(given.ttl) || (given.ttl as number) < 0 || (given.ttl as number) > 2 ** 31) throw invalid("parameters.ttl must be an integer from 0 to 2^31.");
    ttl = given.ttl as number;
  }
  return { method, updateKeys, nextKeyHashes, witness, watchers, deactivated, ttl };
}

export type VhResolveOptions = {
  /** At most one of these selects a version; none selects the latest. */
  versionId?: string; versionTime?: string; versionNumber?: number;
  /** Refuse a log that is older than, or forks, a version accepted before (see freshness.ts). */
  memory?: VersionMemory;
  /** The current time in ms, for the future-time check. */
  now?: number;
};

export type VhResolutionMetadata = {
  versionId: string; versionTime: string; versionNumber: number; created: string; updated: string; scid: string;
  deactivated: boolean; ttl: number; watchers: string[]; witness: Record<string, unknown>;
  /** The newest version of the whole log, whichever version was selected. */
  latestVersionId: string;
};

export type VhResolution = {
  did: string;
  /** The DID Document of the selected version; null when the DID is deactivated and its latest version was asked for. */
  doc: Record<string, any> | null;
  meta: VhResolutionMetadata;
};

/** Every proof of the entry must be an eddsa-jcs-2022 signature by one of `keys` (named `did:key:<k>#<k>`). */
async function signedBy(entry: VhLogEntry, keys: string[], index: number) {
  const { proof, ...document } = entry;
  if (!Array.isArray(proof) || !proof.length) throw invalid(`Entry ${index + 1} has no proof.`);
  for (const one of proof) {
    if (!one || typeof one !== "object") throw invalid(`Entry ${index + 1} has a malformed proof.`);
    if (!await verifyDataIntegrityProof(document, one, keys, "assertionMethod")) {
      throw invalid(`Entry ${index + 1} has a proof that is not a valid eddsa-jcs-2022 signature by an authorised key.`);
    }
  }
}

/** Verify a whole did:vh log for `did` and return the selected version (didvh-spec: Resolution Algorithm). */
export async function resolveVhLog(did: string, log: ReadonlyArray<VhLogEntry>, options: VhResolveOptions = {}): Promise<VhResolution> {
  let scid: string;
  try { scid = parseVhDid(did).scid; } catch { throw new VhResolutionError("invalidDid", "Not a did:vh DID."); }

  const selectors = [options.versionId, options.versionTime, options.versionNumber].filter(value => value !== undefined);
  if (selectors.length > 1) throw new VhResolutionError("invalidOptions", "At most one of versionId, versionTime and versionNumber may be given.");
  if (options.versionNumber !== undefined && (!Number.isInteger(options.versionNumber) || options.versionNumber < 1)) throw new VhResolutionError("invalidOptions", "versionNumber must be a positive integer.");
  let requestedTime: number | undefined;
  if (options.versionTime !== undefined) {
    requestedTime = Date.parse(options.versionTime);
    if (Number.isNaN(requestedTime)) throw new VhResolutionError("invalidOptions", "versionTime must be an ISO 8601 time.");
  }
  if (!Array.isArray(log) || !log.length) throw invalid("The DID log is empty.");

  const now = options.now ?? Date.now();
  const states: Array<{ active: ActiveParameters; time: number }> = [];
  let active: ActiveParameters | undefined;
  let previousVersionId = "";
  let previousTime = -Infinity;

  for (let index = 0; index < log.length; index += 1) {
    const entry = log[index]!;
    const label = `Entry ${index + 1}`;
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw invalid(`${label} is not an object.`);
    for (const name of Object.keys(entry)) if (!ENTRY_MEMBERS.includes(name)) throw invalid(`${label} has an unknown member ${JSON.stringify(name)}.`);
    if (active?.deactivated) throw invalid(`${label} follows the entry that deactivated the DID.`);

    // Parameters take effect with their own entry (VH-Log: Activation), except that pre-rotation looks at the previous entry's.
    const previous = active;
    active = applyParameters(previous, entry.parameters, index === 0);

    if (index === 0) {
      if (entry.parameters.scid !== scid) throw invalid("The SCID in the log is not the SCID of the DID.");
      if (!verifyScid(entry)) throw invalid("The SCID does not match the first entry.");
      previousVersionId = scid;
    }

    let version: { number: number; hash: string };
    try { version = parseVersionId(entry.versionId); } catch (cause) { throw invalid(`${label}: ${(cause as Error).message}`); }
    if (version.number !== index + 1) throw invalid(`${label} has version number ${version.number}.`);
    if (version.hash !== entryHash(entry, previousVersionId)) throw invalid(`${label} has an entry hash that does not match its content.`);

    let time: number;
    try { time = parseVersionTime(entry.versionTime); } catch (cause) { throw invalid(`${label}: ${(cause as Error).message}`); }
    if (time <= previousTime) throw invalid(`${label} is not later than the entry before it.`);
    if (time > now + FUTURE_TOLERANCE_MS) throw invalid(`${label} is dated in the future.`);

    if (!entry.state || typeof entry.state !== "object" || Array.isArray(entry.state)) throw invalid(`${label} has no DID Document.`);
    if (entry.state.id !== did) throw invalid(`${label}: the document id must be exactly ${did}.`);

    // Which keys may sign this entry (VH-Log: Authorized Keys).
    let signers: string[];
    if (index === 0) signers = active.updateKeys;
    else if (previous!.nextKeyHashes.length) {
      // Pre-rotation: the entry restates both lists, and every key it authorises was committed by the entry before.
      if (entry.parameters.updateKeys === undefined) throw invalid(`${label} must restate updateKeys: pre-rotation is active.`);
      if (entry.parameters.nextKeyHashes === undefined) throw invalid(`${label} must restate nextKeyHashes: pre-rotation is active.`);
      const committed = new Set(previous!.nextKeyHashes);
      for (const key of active.updateKeys) if (!committed.has(keyHash(key))) throw invalid(`${label} authorises a key that the entry before did not commit to.`);
      signers = active.updateKeys;
    } else signers = previous!.updateKeys;
    await signedBy(entry, signers, index);

    states.push({ active, time });
    previousVersionId = entry.versionId;
    previousTime = time;
  }

  if (options.memory) await checkAndRemember(options.memory, `did:vh:${scid}`, log);

  let selected = log.length - 1;
  if (options.versionId !== undefined) selected = log.findIndex(entry => entry.versionId === options.versionId);
  else if (options.versionNumber !== undefined) selected = options.versionNumber <= log.length ? options.versionNumber - 1 : -1;
  else if (requestedTime !== undefined) {
    selected = -1;
    states.forEach((state, index) => { if (state.time <= requestedTime!) selected = index; });
  }
  if (selected < 0) throw new VhResolutionError("notFound", "No entry of the log matches the requested version.");

  const last = states[states.length - 1]!.active;
  const here = states[selected]!.active;
  const entry = log[selected]!;
  return {
    did,
    doc: last.deactivated && selected === log.length - 1 ? null : entry.state,
    meta: {
      versionId: entry.versionId, versionTime: entry.versionTime, versionNumber: selected + 1,
      created: log[0]!.versionTime, updated: entry.versionTime, scid,
      deactivated: last.deactivated, ttl: here.ttl, watchers: here.watchers, witness: here.witness,
      latestVersionId: log[log.length - 1]!.versionId,
    },
  };
}
