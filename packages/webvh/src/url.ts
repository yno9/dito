/**
 * did:webvh identifier <-> URL. didwebvh-ts derives the same URL internally
 * but does not export it, and a caller that fetches a log itself (to apply its
 * own SSRF policy, caching or transport) needs it before resolving.
 */
export type ParsedDid = { scid: string; domain: string; port?: number; segments: string[] };

const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

function decode(value: string, label: string): string {
  try {
    const decoded = decodeURIComponent(value);
    if (!decoded) throw new Error();
    return decoded;
  } catch { throw new Error(`invalid percent encoding in DID ${label}`); }
}

/** Strict parse of `did:webvh:<scid>:<domain>[%3A<port>][:<path-segment>…]`. */
export function parseDid(did: string): ParsedDid {
  const match = /^did:webvh:([^:]+):([^:]+)((?::[^:]+)*)$/.exec(did);
  if (!match) throw new Error("not a bare did:webvh DID");
  const scid = match[1]!;
  if (!/^[1-9A-HJ-NP-Za-km-z]{46}$/.test(scid)) throw new Error("invalid DID SCID");
  const chunks = match[2]!.split(/%3A/i);
  if (chunks.length > 2) throw new Error("invalid encoded port");
  // A domain that decodes to anything but a bare FQDN (e.g. "evil.com%23.did.md")
  // would pass a later `.endsWith(".did.md")` check yet change meaning once put
  // in a URL, so anything else is rejected before it is compared or fetched.
  const domain = decode(chunks[0]!, "domain").toLowerCase();
  if (!DOMAIN.test(domain) || /^(?:\d+\.){3}\d+$/.test(domain)) throw new Error("DID domain must be a fully qualified DNS name, not an IP address");
  let port: number | undefined;
  if (chunks[1] !== undefined) {
    if (!/^\d{1,5}$/.test(chunks[1])) throw new Error("invalid DID port");
    port = Number(chunks[1]);
    if (port < 1 || port > 65535) throw new Error("invalid DID port");
  }
  const encoded = match[3] ? match[3].slice(1).split(":") : [];
  if (encoded.some(segment => !segment)) throw new Error("DID path segments must not be empty");
  const segments = encoded.map(segment => {
    const decoded = decode(segment, "path segment");
    if (decoded === "." || decoded === ".." || /[\\/\0]/.test(decoded) || decoded.trim() !== decoded) throw new Error("invalid DID path segment");
    return decoded;
  });
  return { scid, domain, port, segments };
}

/** The HTTPS URL of a DID's `did.jsonl`. */
export function didToLogUrl(did: string): string {
  const { domain, port, segments } = parseDid(did);
  const host = port ? `${domain}:${port}` : domain;
  return segments.length ? `https://${host}/${segments.map(encodeURIComponent).join("/")}/did.jsonl` : `https://${host}/.well-known/did.jsonl`;
}
