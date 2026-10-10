/**
 * did:webvh log validation for did.md, with no Node or Cloudflare
 * dependency, so the same code runs in the did.md host
 * (server/host/identity-host.ts), the Cloudflare Worker, and the browser
 * wallet (which validates a log before publishing it anywhere that has no
 * server-side gatekeeper, e.g. the user's own GitHub Pages).
 *
 * The did:webvh mechanics -- SCID, entry hashes, versions, times,
 * pre-rotation, portability, Data Integrity proofs, witnesses, the did:web
 * mirror -- are didwebvh-ts's (through packages/webvh). What remains here is
 * did.md's own policy on top: an entry-count limit, the publication-location
 * check, an independent proof-authorization check, and the atproto shape of
 * the served did:web document.
 */
import { generateParallelDidWeb } from "didwebvh-ts";
import { currentParameters, parseLog, resolveLog, serializeLog, type DIDLog } from "../../webvh/src/log.ts";
import { didToLogUrl } from "../../webvh/src/url.ts";
import { verifyDataIntegrityProof } from "../../webvh/src/proof.ts";

export const MAX_ENTRIES = 10_000;
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export type Obj = Record<string, Json>;
export type Entry = { versionId: string; versionTime: string; parameters: Obj; state: Obj; proof: Proof[] };
export type Proof = { type: string; cryptosuite: string; proofPurpose: string; verificationMethod: string; proofValue: string; created?: string };
export type WitnessFile = Array<{ versionId: string; proof: Proof[] }>;
/** Parameters in force after the last entry, as didwebvh-ts resolves them. */
export type Params = {
  scid?: string; updateKeys: string[]; nextKeyHashes: string[]; witness: unknown; watchers: string[]; portable: boolean; deactivated: boolean;
};
export class Invalid extends Error {}

export function isObj(value: unknown): value is Obj { return typeof value === "object" && value !== null && !Array.isArray(value); }
export function asObj(value: unknown, label: string): Obj { if (!isObj(value)) throw new Invalid(`${label} must be an object`); return value; }
export function own<T extends object>(v: T, key: string) { return Object.prototype.hasOwnProperty.call(v, key); }
export function onlyKeys(value: Obj, allowed: string[], label: string) { for (const key of Object.keys(value)) if (!allowed.includes(key)) throw new Invalid(`${label}.${key} is not defined by did:webvh:1.0`); }

/** Strict `did.jsonl` body -> entries (newline-terminated, one JSON entry per line). */
export function parseJsonl(input: string): Entry[] {
  try { return parseLog(input) as unknown as Entry[]; }
  catch (error) { throw new Invalid(error instanceof Error ? error.message : "invalid did.jsonl"); }
}
export function serialise(entries: Entry[]) { return serializeLog(entries as unknown as DIDLog); }

/** `did-witness.json`: an array of `{ versionId, proof[] }`, checked by didwebvh-ts against the log. */
export function parseWitnessFile(input: string): WitnessFile {
  let parsed: unknown; try { parsed = JSON.parse(input); } catch { throw new Invalid("invalid did-witness.json"); }
  if (!Array.isArray(parsed)) throw new Invalid("did-witness.json must be an array");
  return parsed.map((item, index) => {
    const record = asObj(item, `witness[${index}]`); onlyKeys(record, ["versionId", "proof"], `witness[${index}]`);
    if (typeof record.versionId !== "string" || !Array.isArray(record.proof) || !record.proof.every(isObj)) throw new Invalid("invalid witness entry");
    return { versionId: record.versionId, proof: record.proof as unknown as Proof[] };
  });
}

/**
 * Full v1.0 validation used before every disk write. `expectedLogUrl` is the
 * publication location the log must end at (or undefined to skip that check).
 */
export async function validateLogAt(entries: Entry[], witnessFile: WitnessFile, expectedLogUrl?: string) {
  if (!entries.length || entries.length > MAX_ENTRIES) throw new Invalid("invalid number of log entries");
  let resolved;
  try {
    resolved = await resolveLog(entries as unknown as DIDLog, { witnessProofs: witnessFile as never });
  } catch (error) {
    throw new Invalid(error instanceof Error ? error.message : "invalid did:webvh log");
  }
  // Defense in depth on the one check that authorizes every write: each entry
  // must carry a Data Integrity proof made by a key the log itself authorizes
  // -- the genesis/pre-rotated updateKeys, or the previous entry's updateKeys
  // when pre-rotation is off. (didwebvh-ts 2.8.0 accepted `proof: []`; see
  // JOURNAL.md. This stays as an independent second check.)
  let previous: { updateKeys: string[]; nextKeyHashes: string[] } | undefined;
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i]!;
    const params = currentParameters(entries.slice(0, i + 1) as unknown as DIDLog) as { updateKeys?: string[]; nextKeyHashes?: string[] };
    const now = { updateKeys: params.updateKeys ?? [], nextKeyHashes: params.nextKeyHashes ?? [] };
    const signingKeys = i === 0 || previous!.nextKeyHashes.length > 0 ? now.updateKeys : previous!.updateKeys;
    const unsigned = { versionId: entry.versionId, versionTime: entry.versionTime, parameters: entry.parameters, state: entry.state };
    if (!Array.isArray(entry.proof) || !signingKeys.length
      || !(await Promise.all(entry.proof.map(proof => verifyDataIntegrityProof(unsigned, proof, signingKeys)))).some(Boolean)) {
      throw new Invalid("no valid authorized Data Integrity proof");
    }
    previous = now;
  }
  const latest = entries[entries.length - 1]!;
  if (expectedLogUrl !== undefined && didToLogUrl(latest.state.id as string) !== expectedLogUrl) throw new Invalid("current state.id does not designate this publication location");
  const meta = resolved.meta;
  const parameters: Params = {
    scid: meta.scid, updateKeys: meta.updateKeys, nextKeyHashes: meta.nextKeyHashes, witness: meta.witness ?? {}, watchers: meta.watchers ?? [],
    portable: meta.portable, deactivated: meta.deactivated,
  };
  return { latest, parameters };
}

/**
 * The did:web document served next to did.jsonl. didwebvh-ts derives the
 * mirror (did:web ids, the `#files`/`#whois` services, `alsoKnownAs`); what is
 * added is did.md's atproto shape: `at://` aliases, service and key ordering,
 * and `{ uri }` service endpoints.
 */
export function mirrorDocument(state: Obj, webvhDid: string, options: { hostedResources?: boolean } = {}): Obj {
  const original = Array.isArray(state.service) ? state.service : [];
  const declared = (suffix: string) => original.some(service => isObj(service) && String(service.id ?? "").endsWith(suffix));
  const transformed = generateParallelDidWeb(webvhDid, JSON.parse(JSON.stringify(state))) as unknown as Obj;
  let services = Array.isArray(transformed.service) ? [...transformed.service] : [];
  if (options.hostedResources === false) {
    // didwebvh-ts adds #files/#whois when absent; a host that serves no such
    // resources (GitHub Pages) mirrors only what the log itself declares.
    services = services.filter(service => !(isObj(service) && ((service.id === "#files" && !declared("#files")) || (service.id === "#whois" && !declared("#whois")))));
  }
  // Full DIDComm services stay -- do not drop #didcomm.
  // Order: #atproto_pds first, string endpoints next, DIDComm last.
  // Shape: @atproto/identity zod accepts serviceEndpoint: string | { uri } |
  // string[] but rejects DIDComm Core's accept[] / routingKeys[] arrays. Keep
  // the service; express the endpoint as { uri } in the did:web mirror. Full
  // accept/routingKeys remain in did.jsonl.
  const normalizeEndpoint = (endpoint: unknown): unknown => {
    if (!isObj(endpoint)) return endpoint;
    const uri = endpoint.uri;
    return typeof uri === "string" ? { uri } : endpoint;
  };
  const serviceRank = (service: unknown): number => {
    if (!isObj(service)) return 9;
    if (String(service.id ?? "").endsWith("#atproto_pds")) return 0;
    const endpoint = service.serviceEndpoint;
    if (typeof endpoint === "string") return 1;
    if (Array.isArray(endpoint)) return 2;
    if (isObj(endpoint)) return 3;
    return 4;
  };
  transformed.service = services
    .map(service => isObj(service) ? { ...service, serviceEndpoint: normalizeEndpoint(service.serviceEndpoint) } : service)
    .sort((a, b) => serviceRank(a) - serviceRank(b));

  const webDid = String(transformed.id);
  const previous = Array.isArray(transformed.alsoKnownAs) ? transformed.alsoKnownAs.filter(value => typeof value === "string") as string[] : [];
  const atAliases = previous.filter(value => value.startsWith("at://"));
  const host = webDid.slice("did:web:".length).split(":")[0]!.replace(/%3A.*$/i, "");
  const hasAtprotoService = original.some(service => isObj(service) && String(service.id ?? "").endsWith("#atproto_pds"));
  const hasAtprotoVm = Array.isArray(transformed.verificationMethod) && transformed.verificationMethod.some(vm => isObj(vm) && String(vm.id ?? "").endsWith("#atproto"));
  if ((hasAtprotoService || hasAtprotoVm) && !atAliases.includes(`at://${host}`)) atAliases.push(`at://${host}`);
  // #atproto first among verificationMethods (order only -- no key removal).
  if (Array.isArray(transformed.verificationMethod)) {
    const rank = (id: string) => id.endsWith("#atproto") ? 0 : id.endsWith("#pass-1") ? 1 : 2;
    transformed.verificationMethod = [...transformed.verificationMethod].sort((a, b) =>
      rank(isObj(a) ? String(a.id ?? "") : "") - rank(isObj(b) ? String(b.id ?? "") : ""));
  }
  transformed.alsoKnownAs = [...new Set([...atAliases, ...previous.filter(value => value !== webDid && !value.startsWith("at://")), webvhDid])];
  return transformed;
}
