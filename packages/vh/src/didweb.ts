/**
 * did:web as a shadow of did:vh (PLAN-didvh.md §1.2, REPORT-didvh.md §8).
 *
 * did:vh is the identity. A did:web DID names a web location, so it can serve
 * where a did:web is expected, but it is no better than the host that serves it:
 * no hash chain, no witnesses, no watchers. So its document is *derived* from the
 * latest did:vh document, never written separately:
 *
 *  - every `did:vh:<SCID>` in the document becomes the did:web DID;
 *  - `alsoKnownAs` becomes `[did:vh:<SCID>?src=<the location>]`, and nothing else: the DID it is a shadow of, with the place
 *    its log is published at (the location is the did:web DID's own host and path, so nothing is added that the DID does not say).
 *
 * A verifier takes did:vh as the truth and accepts a did:web document only if it
 * equals what this derivation gives for the did:vh document that, in turn, names
 * the did:web DID in its own `alsoKnownAs`: a link in both directions.
 */
import { canonicalize } from "./jcs.ts";
import { srcAlias } from "./aliases.ts";
import { parseWebLocation, type SrcOptions } from "./src.ts";

/** `did:web:<host>[%3A<port>][:<path>…]` for a web location. */
export function didWebFor(src: string, options: SrcOptions = {}): string {
  const where = parseWebLocation(src, options);
  const host = where.port === undefined ? where.host : `${where.host}%3A${where.port}`;
  return ["did:web", host, ...where.segments].join(":");
}

/** The web location a did:web DID names (`did:web:alice.did.md` is `https://alice.did.md`): the inverse of `didWebFor`. */
export function srcOfDidWeb(webDid: string): string {
  const parts = webDid.split(":");
  if (parts[0] !== "did" || parts[1] !== "web" || parts.length < 3 || parts.some(part => part === "")) throw new Error("Not a did:web DID.");
  try { return ["https://" + decodeURIComponent(parts[2]!), ...parts.slice(3).map(decodeURIComponent)].join("/"); } catch { throw new Error("Not a did:web DID."); }
}

function replaceDid(value: unknown, vhDid: string, webDid: string): unknown {
  if (typeof value === "string") {
    if (value === vhDid) return webDid;
    return value.startsWith(vhDid) && /^[#?/]/.test(value.slice(vhDid.length)) ? webDid + value.slice(vhDid.length) : value;
  }
  if (Array.isArray(value)) return value.map(item => replaceDid(item, vhDid, webDid));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, replaceDid(item, vhDid, webDid)]));
  return value;
}

/** The did:web document derived from a did:vh document. */
export function deriveDidWebDocument(vhDocument: Record<string, any>, webDid: string): Record<string, any> {
  const vhDid = vhDocument.id;
  if (typeof vhDid !== "string" || !/^did:vh:/.test(vhDid)) throw new Error("Not a did:vh document.");
  const { alsoKnownAs: _dropped, ...rest } = replaceDid(vhDocument, vhDid, webDid) as Record<string, any>;
  return { ...rest, alsoKnownAs: [srcAlias(vhDid, srcOfDidWeb(webDid))] };
}

export type ShadowCheck = { ok: true } | { ok: false; reason: string };

/**
 * Whether `webDocument` (fetched for `webDid`) is a faithful shadow of the
 * did:vh document `vhDocument` (the verified, latest one).
 */
export function checkDidWebShadow(vhDocument: Record<string, any>, webDid: string, webDocument: unknown): ShadowCheck {
  const links = Array.isArray(vhDocument.alsoKnownAs) ? vhDocument.alsoKnownAs : [];
  if (!links.includes(webDid)) return { ok: false, reason: `The did:vh document does not name ${webDid} in alsoKnownAs.` };
  if (!webDocument || typeof webDocument !== "object" || Array.isArray(webDocument)) return { ok: false, reason: "The did:web document is not an object." };
  let expected: Record<string, any>;
  try { expected = deriveDidWebDocument(vhDocument, webDid); } catch (cause) { return { ok: false, reason: (cause as Error).message }; }
  if (canonicalize(expected) !== canonicalize(webDocument)) return { ok: false, reason: "The did:web document is not what the did:vh document derives." };
  return { ok: true };
}
