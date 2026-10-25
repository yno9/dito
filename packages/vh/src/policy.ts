/**
 * What a host that publishes did:vh logs checks before it stores one: the log
 * verifies (resolveVhLog), it is not absurdly long, and, for a host that names
 * its locations (`alice.did.md`), the current document names that location's
 * did:web DID in `alsoKnownAs`.
 *
 * That last rule is what binds a name to a log. A did:vh DID contains no host, so
 * without the rule any valid log could be put at `alice.did.md`, and the name would
 * mean nothing. With it, the
 * log's own signed document says "this is alice.did.md", which is also what
 * lets anyone check the did:web shadow against the did:vh document (didweb.ts).
 */
import { parseVhDid } from "./did.ts";
import type { VhLogEntry } from "./log.ts";
import { VhResolutionError, applyParameters, resolveVhLog, type ActiveParameters } from "./verify.ts";

export const MAX_VH_ENTRIES = 10_000;

export type VhPolicy = {
  /** The did:web DID of the location being published to; the current document must list it. */
  webDid?: string;
  now?: number;
};

export type CheckedVhLog = {
  did: string;
  latest: VhLogEntry;
  /** The parameters in force after the last entry (as the host reads them). */
  parameters: { scid: string; updateKeys: string[]; nextKeyHashes: string[]; witness: Record<string, unknown>; watchers: string[]; portable: false; deactivated: boolean };
};

export async function validateVhLogAt(entries: ReadonlyArray<VhLogEntry>, policy: VhPolicy = {}): Promise<CheckedVhLog> {
  if (!Array.isArray(entries) || !entries.length || entries.length > MAX_VH_ENTRIES) throw new VhResolutionError("invalidLog", "Invalid number of log entries.");
  const scid = entries[0]?.parameters?.scid;
  let did: string;
  try { did = `did:vh:${parseVhDid(`did:vh:${scid}`).scid}`; } catch { throw new VhResolutionError("invalidLog", "The first entry has no valid SCID."); }
  await resolveVhLog(did, entries, { now: policy.now });

  let active: ActiveParameters | undefined;
  entries.forEach((entry, index) => { active = applyParameters(active, entry.parameters, index === 0); });
  const latest = entries[entries.length - 1]!;
  if (policy.webDid !== undefined && !active!.deactivated) {
    const names = Array.isArray(latest.state.alsoKnownAs) ? latest.state.alsoKnownAs : [];
    if (!names.includes(policy.webDid)) throw new VhResolutionError("invalidLog", `The current document must name ${policy.webDid} in alsoKnownAs: that is what makes this log the one for that location.`);
  }
  return {
    did, latest,
    parameters: { scid: scid as string, updateKeys: active!.updateKeys, nextKeyHashes: active!.nextKeyHashes, witness: active!.witness, watchers: active!.watchers, portable: false, deactivated: active!.deactivated },
  };
}
