import { ed25519 } from "@noble/curves/ed25519.js";
import { base64urlDecode } from "../packages/wallet/src/keys.ts";
import { authenticationPublicKey, fetchVhLog, resolveVhFromWatchers, resolveVhLog, parseVhDid } from "../packages/vh/src/index.ts";

/**
 * Verifies a compact EdDSA JWS whose `kid` header is a DID URL of a relying party: a did:vh (`did:vh:<SCID>[?src=<location>]#<fragment>`)
 * or a did:web (`did:web:<host>#<fragment>`). Used for a JAR (RFC 9101) Authorization Request object signed by a relying
 * party's own DID key.
 *
 * A did:vh DID names no location, so the RP's log comes from where the request says (`?src=`, the DID URL parameter of
 * didvh-spec: a browser fetches it on the person's behalf) or, without one, from `watchers` (the wallet's own host). Either
 * way nothing is trusted but the log itself: it must verify in full and describe exactly the DID the request names.
 * A did:web names its host, so its document is the one served at `https://<host>/.well-known/did.json` (and must name that DID).
 * Returns the verified JWT payload plus the resolver's `service` array, so the caller can also check the request's claimed
 * redirect_uri against what the RP's own DID document publishes (PLAN6 §0.3bis).
 */
export async function verifyRequestObjectJws(jwt: string, options: { watchers?: string[] } = {}): Promise<{ payload: Record<string, unknown>; rpDid: string; service: any[]; document: Record<string, any> }> {
  const parts = jwt.split(".");
  if (parts.length !== 3) throw new Error("The request object is malformed.");
  const encoder = new TextEncoder();
  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    header = JSON.parse(new TextDecoder().decode(base64urlDecode(parts[0]!, "request object header")));
    payload = JSON.parse(new TextDecoder().decode(base64urlDecode(parts[1]!, "request object payload")));
  } catch { throw new Error("The request object is malformed."); }
  if (header.alg !== "EdDSA" || typeof header.kid !== "string") throw new Error("The request object header is invalid.");
  const hashIndex = header.kid.indexOf("#");
  if (hashIndex <= 0) throw new Error("The request object kid has no fragment.");
  const { did: rpDid, document } = await resolveRpDocument(header.kid.slice(0, hashIndex), options);
  const publicKey = authenticationPublicKey(document, rpDid, `${rpDid}${header.kid.slice(hashIndex)}`);
  const signature = base64urlDecode(parts[2]!, "request object signature");
  if (!ed25519.verify(signature, encoder.encode(`${parts[0]}.${parts[1]}`), publicKey)) throw new Error("The request object signature is invalid.");
  return { payload, rpDid, service: Array.isArray(document.service) ? document.service : [], document };
}

/** A relying party's DID: a did:vh, or a did:web of a plain host (no port, no path). */
export function isRpDid(value: unknown): value is string {
  return typeof value === "string" && (value.startsWith("did:vh:") || (!/^did:web:[0-9.]+$/.test(value) && /^did:web:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(value)));
}

const MAX_DID_DOCUMENT_BYTES = 256 * 1024;

/** The verified current document of a relying party named by `did:vh:<SCID>`, `did:vh:<SCID>?src=<location>` or `did:web:<host>`. */
export async function resolveRpDocument(didUrl: string, options: { watchers?: string[]; fetch?: typeof fetch } = {}): Promise<{ did: string; document: Record<string, any> }> {
  const queryIndex = didUrl.indexOf("?");
  const did = queryIndex === -1 ? didUrl : didUrl.slice(0, queryIndex);
  if (did.startsWith("did:web:")) {
    if (queryIndex !== -1 || !isRpDid(did)) throw new Error("The relying party's did:web DID is not a plain host.");
    const response = await (options.fetch ?? fetch)(`https://${did.slice("did:web:".length)}/.well-known/did.json`, { cache: "no-store", redirect: "error" });
    if (!response.ok) throw new Error("The relying party's DID document was not found.");
    const text = await response.text();
    if (text.length > MAX_DID_DOCUMENT_BYTES) throw new Error("The relying party's DID document is too large.");
    const document = JSON.parse(text) as Record<string, any>;
    if (!document || typeof document !== "object" || document.id !== did) throw new Error("The relying party's DID document does not name its DID.");
    return { did, document };
  }
  if (!did.startsWith("did:vh:")) throw new Error("The relying party is not a did:vh or did:web DID.");
  parseVhDid(did);
  const src = queryIndex === -1 ? undefined : new URLSearchParams(didUrl.slice(queryIndex + 1)).get("src") ?? undefined;
  const resolved = src
    ? await resolveVhLog(did, (await fetchVhLog(src)).log)
    : await resolveVhFromWatchers(did, { watchers: options.watchers ?? [] });
  const document = resolved.doc as Record<string, any> | null;
  if (!document) throw new Error("The relying party's DID is deactivated.");
  return { did, document };
}
