/**
 * The OAuth `login_hint` the wallet accepts: the host an identity is published at.
 *
 * It names a did.md subdomain ("alice.did.md") or a bring-your-own domain
 * ("digitalcommons.jp"). Either way it is only ever compared with the host segment of the
 * loaded identity's DID (did:webvh:<scid>:<host>), to pin the consent screen to the identity
 * the relying party asked for -- it grants nothing by itself.
 */
const LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
const HOST = new RegExp(`^(?:${LABEL}\\.)+[a-z][a-z0-9-]*[a-z0-9]$`);

/** The normalized host, or null when `hint` is not a plain DNS hostname (no IPs, ports, paths). */
export function parseLoginHost(hint: unknown): string | null {
  if (typeof hint !== "string") return null;
  const host = hint.toLowerCase();
  return host.length <= 253 && HOST.test(host) ? host : null;
}

/** The host segment of a did:webvh identifier -- did:webvh:<scid>:<host>. */
export function didHost(did: unknown): string | null {
  const match = typeof did === "string" ? /^did:webvh:[^:]+:(.+)$/.exec(did) : null;
  return match ? match[1]! : null;
}

/** True when the identity `did` is published at `host`. */
export function didIsHostedAt(did: unknown, host: string): boolean {
  return didHost(did) === host;
}
