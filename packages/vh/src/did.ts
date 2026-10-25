/** `did:vh:<SCID>`: the whole identifier is the SCID (didvh-spec: Method-Specific Identifier). */
export const VH_METHOD = "did:vh:1.0";
export const SCID_PLACEHOLDER = "{SCID}";

/** A SHA-256 multihash in base58btc: 34 bytes, 46 characters, no 0, O, I or l. */
const SCID = /^[1-9A-HJ-NP-Za-km-z]{46}$/;

export function isScid(value: unknown): value is string {
  return typeof value === "string" && SCID.test(value);
}

/** `did:vh:<scid>` for a SCID, or for the placeholder while a log is being created. */
export function vhDid(scid: string): string {
  if (scid !== SCID_PLACEHOLDER && !isScid(scid)) throw new Error("Invalid SCID.");
  return `did:vh:${scid}`;
}

/** The SCID of a bare `did:vh` DID. A DID URL (path, query, fragment) is not a DID. */
export function parseVhDid(did: string): { scid: string } {
  const match = /^did:vh:([^:/?#]+)$/.exec(did);
  if (!match || !isScid(match[1])) throw new Error("Not a did:vh DID.");
  return { scid: match[1] };
}
