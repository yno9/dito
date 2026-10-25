/**
 * Getting the log of a did:vh DID from watchers: web origins that serve `GET /log?scid=` (a did.md host does, under
 * any host name). The watchers are the *verifier's* choice, never the token's or the message's, so what is verified
 * cannot send the verifier to a log of its own choosing. Nothing a watcher says is trusted: the log is verified in full.
 */
import { VhHostingClient } from "./hosting.ts";
import { parseVhLog } from "./log.ts";
import { parseVhDid } from "./did.ts";
import { resolveVhLog, VhResolutionError, type VhResolution } from "./verify.ts";
import type { VersionMemory } from "./freshness.ts";

export type WatcherSources = { watchers: readonly string[]; fetch?: typeof fetch; memory?: VersionMemory };

/**
 * Resolves a did:vh DID from the first watcher that has its log. A log that does not verify is an error, not a reason
 * to ask the next watcher.
 */
export async function resolveVhFromWatchers(did: string, sources: WatcherSources): Promise<VhResolution> {
  const { scid } = parseVhDid(did);
  const client = new VhHostingClient({ fetch: sources.fetch });
  let text: string | null = null;
  for (const watcher of sources.watchers) {
    try { text = await client.readByScid(watcher, scid); } catch { text = null; }
    if (text !== null) break;
  }
  if (text === null) throw new VhResolutionError("notFound", "The DID log of this did:vh DID was not found at any accepted watcher.");
  return resolveVhLog(did, parseVhLog(text), sources.memory ? { memory: sources.memory } : {});
}
