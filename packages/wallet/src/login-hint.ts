/**
 * The OAuth `login_hint` the wallet accepts: the host an identity is published at.
 *
 * It names a did.md subdomain ("alice.did.md") or a bring-your-own domain
 * ("digitalcommons.jp"). Either way it is only ever compared with the locations the loaded
 * identity's own document names, to pin the consent screen to the identity the relying party
 * asked for -- it grants nothing by itself.
 */
import { locationsOf } from "../../vh/src/index.ts";

const LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
const HOST = new RegExp(`^(?:${LABEL}\\.)+[a-z][a-z0-9-]*[a-z0-9]$`);

/** The normalized host, or null when `hint` is not a plain DNS hostname (no IPs, ports, paths). */
export function parseLoginHost(hint: unknown): string | null {
  if (typeof hint !== "string") return null;
  const host = hint.toLowerCase();
  return host.length <= 253 && HOST.test(host) ? host : null;
}

/** The hosts (`alice.did.md`) a DID document says its log is published at, in the order it lists them. */
export function locationHosts(did: string, document: Record<string, any>): string[] {
  return locationsOf(did, document).flatMap(location => { try { return [new URL(location.src).host]; } catch { return []; } });
}

/** True when the identity `did`, whose current document is `document`, is published at `host`. */
export function isHostedAt(did: string, document: Record<string, any>, host: string): boolean {
  return locationHosts(did, document).includes(host);
}
