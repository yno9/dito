import { InMemoryVersionMemory, authenticationPublicKey, maySignIn, parseDid, resolveDidWebvh, type VersionMemory } from "../webvh/src/index.ts";
import { VhHostingClient, parseVhDid, parseVhLog, resolveVhLog } from "../vh/src/index.ts";

export interface VerifiedSigner {
  sub: string;
  method: "jwk" | "did-webvh" | "did-vh";
  publicKeyJwk: JsonWebKey;
}

function decodePart(value: string, label: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw new Error(`${label} is not base64url`);
  try { return new Uint8Array(Buffer.from(value, "base64url")); }
  catch { throw new Error(`${label} is not base64url`); }
}

function parseHeader(jwt: string): Record<string, unknown> {
  const parts = jwt.split(".");
  if (parts.length !== 3 || !parts.every(Boolean)) throw new Error("JWT is malformed");
  try {
    const value = JSON.parse(new TextDecoder().decode(decodePart(parts[0]!, "JWT header")));
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error();
    return value;
  } catch { throw new Error("JWT header is malformed"); }
}

export async function jwkThumbprint(jwk: JsonWebKey): Promise<string> {
  let required: Record<string, string | undefined>;
  switch (jwk.kty) {
    case "OKP": required = { crv: jwk.crv, kty: jwk.kty, x: jwk.x }; break;
    case "EC": required = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }; break;
    case "RSA": required = { e: jwk.e, kty: jwk.kty, n: jwk.n }; break;
    case "oct": required = { k: jwk.k, kty: jwk.kty }; break;
    default: throw new Error("unsupported JWK key type");
  }
  if (Object.values(required).some(value => typeof value !== "string" || !value)) throw new Error("JWK is missing a thumbprint member");
  const canonical = `{${Object.keys(required).sort().map(key => `${JSON.stringify(key)}:${JSON.stringify(required[key])}`).join(",")}}`;
  return Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical))).toString("base64url");
}

export async function verifyViaEmbeddedJwk(jwt: string, jwk: JsonWebKey): Promise<VerifiedSigner> {
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string" || jwk.d !== undefined) throw new Error("embedded JWK must be an Ed25519 public key");
  const parts = jwt.split(".");
  if (parts.length !== 3) throw new Error("JWT is malformed");
  const header = parseHeader(jwt);
  if (header.alg !== "EdDSA") throw new Error("JWT algorithm must be EdDSA");
  let key: CryptoKey;
  try { key = await crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, ["verify"]); }
  catch { throw new Error("embedded JWK is invalid"); }
  const valid = await crypto.subtle.verify({ name: "Ed25519" }, key, decodePart(parts[2]!, "JWT signature"), new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
  if (!valid) throw new Error("JWT signature is invalid");
  return { sub: await jwkThumbprint(jwk), method: "jwk", publicKeyJwk: jwk };
}

// The pieces of a did:webvh identifier a caller needs to apply an allowlist
// (domain suffix) before anything is fetched. The strict parse (FQDN-only
// domain, no IP literals, sane port/path, SCID shape) is packages/webvh's, so
// a domain like "evil.com%23.did.md" is refused before it is compared or
// put in a URL.
export function parseWebvhDid(did: string): { domain: string; port?: number; segments: string[] } {
  const { domain, port, segments } = parseDid(did);
  return { domain, port, segments };
}

// A resolved document's own freshness window: short enough that a key
// rotation is still visible almost immediately, long enough to absorb the
// network round trip's cost when the *same* DID is resolved again within a
// few seconds -- e.g. an OID4VP direct_post approval, then whatever
// downstream request re-verifies the same wallet's signature a moment
// later. Not a general-purpose HTTP cache: only resolveDidWebvhDocument's
// own callers benefit, and only for exactly this DID-keyed lookup.
const DID_DOCUMENT_CACHE_TTL_MS = 60_000;
const didDocumentCache = new Map<string, { document: Record<string, unknown>; expiresAt: number }>();

function cachedDidDocument(did: string): Record<string, unknown> | undefined {
  const cached = didDocumentCache.get(did);
  if (!cached) return undefined;
  if (cached.expiresAt <= Date.now()) { didDocumentCache.delete(did); return undefined; }
  return cached.document;
}

// Opportunistic sweep on every write instead of a timer -- this process
// resolves at most a few dozen distinct DIDs at once in practice, so an
// unbounded timer isn't worth it, but nothing should silently grow forever
// either.
function setCachedDidDocument(did: string, document: Record<string, unknown>): void {
  const now = Date.now();
  for (const [key, value] of didDocumentCache) if (value.expiresAt <= now) didDocumentCache.delete(key);
  didDocumentCache.set(did, { document, expiresAt: now + DID_DOCUMENT_CACHE_TTL_MS });
}

// Resolves a did:webvh DID by fetching its published log over HTTPS and
// validating the WHOLE log (hash chain, pre-rotation, proofs, witnesses) with
// didwebvh-ts before trusting the latest DID Document. The URL is derived and
// fetched here, not by the library, so this caller's own policy applies (the
// allowed-domain suffix, no redirects to other hosts beyond fetch's default,
// the short cache below). Cached briefly (see DID_DOCUMENT_CACHE_TTL_MS) --
// the live fetch is dominated by DNS/TLS/round-trip latency, not payload size.
export async function resolveDidWebvhDocument(did: string, allowedDomainSuffix?: string): Promise<Record<string, unknown>> {
  if (allowedDomainSuffix) {
    const { domain } = parseWebvhDid(did);
    if (domain !== allowedDomainSuffix && !domain.endsWith(`.${allowedDomainSuffix}`)) throw new Error("DID domain is not an accepted issuer domain");
  }
  const cached = cachedDidDocument(did);
  if (cached) return cached;
  const document = (await resolveDidWebvh(did)).doc as unknown as Record<string, unknown>;
  setCachedDidDocument(did, document);
  return document;
}

/** The key of a method that may sign the user in (an id_token's `kid`). */
async function resolveDidWebvhSignInKey(did: string, verificationMethod: string): Promise<Uint8Array> {
  const document = await resolveDidWebvhDocument(did);
  if (!maySignIn(document, did, verificationMethod)) throw new Error("did:webvh authentication method may not sign in");
  return authenticationPublicKey(document, did, verificationMethod);
}

export async function verifyViaDidWebvh(jwt: string, kid: string, allowedDomainSuffix?: string): Promise<VerifiedSigner> {
  const hashIndex = kid.indexOf("#");
  if (hashIndex <= 0) throw new Error("kid is not a DID with a fragment");
  const did = kid.slice(0, hashIndex);
  if (!did.startsWith("did:webvh:")) throw new Error("kid is not a did:webvh DID");
  if (allowedDomainSuffix) {
    const { domain } = parseWebvhDid(did);
    if (domain !== allowedDomainSuffix && !domain.endsWith(`.${allowedDomainSuffix}`)) throw new Error("kid domain is not an accepted issuer domain");
  }
  const parts = jwt.split(".");
  if (parts.length !== 3) throw new Error("JWT is malformed");
  const header = parseHeader(jwt);
  if (header.alg !== "EdDSA") throw new Error("JWT algorithm must be EdDSA");
  const rawKey = await resolveDidWebvhSignInKey(did, kid);
  const jwk: JsonWebKey = { kty: "OKP", crv: "Ed25519", x: Buffer.from(rawKey).toString("base64url") };
  let key: CryptoKey;
  try { key = await crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, ["verify"]); }
  catch { throw new Error("resolved did:webvh authentication key is invalid"); }
  const valid = await crypto.subtle.verify({ name: "Ed25519" }, key, decodePart(parts[2]!, "JWT signature"), new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
  if (!valid) throw new Error("JWT signature is invalid");
  return { sub: did, method: "did-webvh", publicKeyJwk: jwk };
}

/**
 * The subject an OIDC relying party should key an account on. A did:webvh DID
 * names its current location (`did:webvh:<scid>:<host>`), and the string changes
 * when the identity moves; only the SCID is the identity (the SCID is derived
 * from the genesis entry, never from where the log is served). So a did:webvh
 * DID becomes `did:webvh:<scid>`, with the method kept in the value so that a
 * SCID of another method can never collide with it. Anything else (a JWK
 * thumbprint) is already stable and is returned as is.
 */
export function stableSubject(sub: string): string {
  // A did:vh DID is its SCID already: nothing in it moves.
  try { return parseVhDid(sub) && sub; } catch { /* not a did:vh DID */ }
  try { return `did:webvh:${parseDid(sub).scid}`; } catch { return sub; }
}

/**
 * Where to get the log of a did:vh DID, which names no location. `watchers` are web origins that serve
 * `GET /log?scid=` (a did.md host does, under any host name); they are the verifier's choice, not the token's,
 * so a token cannot send the verifier to a log of its own choosing. `memory` is what has been seen before: a log
 * older than, or forking, one accepted is refused (the default lives as long as the process).
 */
export type VhSources = { watchers: string[]; fetch?: typeof fetch; memory?: VersionMemory };

const vhMemory = new InMemoryVersionMemory();

/**
 * Resolves a did:vh DID from the verifier's watchers: the first that has the log, verified in full. A log that does
 * not verify is an error, not a reason to ask the next watcher. With `allowedDomainSuffix`, the DID's document must
 * also name a did:web DID under that domain (what a did.md-hosted identity does).
 */
export async function resolveDidVhDocument(did: string, sources: VhSources, allowedDomainSuffix?: string): Promise<Record<string, unknown>> {
  const { scid } = parseVhDid(did);
  // The cache holds what was verified, not what was allowed: the issuer-domain rule applies to a cached document too.
  const document = cachedDidDocument(did) ?? await fetchDidVhDocument(did, scid, sources);
  if (allowedDomainSuffix) {
    const names: unknown[] = Array.isArray(document.alsoKnownAs) ? document.alsoKnownAs : [];
    const accepted = names.some(name => typeof name === "string" && name.startsWith("did:web:") && (() => {
      const host = name.slice("did:web:".length).split(":")[0]!.replace(/%3A.*$/i, "").toLowerCase();
      return host === allowedDomainSuffix || host.endsWith(`.${allowedDomainSuffix}`);
    })());
    if (!accepted) throw new Error("DID is not an accepted issuer domain");
  }
  return document;
}

async function fetchDidVhDocument(did: string, scid: string, sources: VhSources): Promise<Record<string, unknown>> {
  const client = new VhHostingClient({ fetch: sources.fetch });
  let text: string | null = null;
  for (const watcher of sources.watchers) {
    try { text = await client.readByScid(watcher, scid); } catch { text = null; }
    if (text !== null) break;
  }
  if (text === null) throw new Error("the DID log of this did:vh DID was not found at any accepted watcher");
  const resolved = await resolveVhLog(did, parseVhLog(text), { memory: sources.memory ?? vhMemory });
  if (!resolved.doc) throw new Error("the did:vh DID is deactivated");
  setCachedDidDocument(did, resolved.doc);
  return resolved.doc;
}

/** Forget every resolved document (tests; a process that must see a rotation at once). */
export function clearDidDocumentCache(): void { didDocumentCache.clear(); }

export async function verifyViaDidVh(jwt: string, kid: string, sources: VhSources, allowedDomainSuffix?: string): Promise<VerifiedSigner> {
  const hashIndex = kid.indexOf("#");
  if (hashIndex <= 0) throw new Error("kid is not a DID with a fragment");
  const did = kid.slice(0, hashIndex);
  if (!did.startsWith("did:vh:")) throw new Error("kid is not a did:vh DID");
  const parts = jwt.split(".");
  if (parts.length !== 3) throw new Error("JWT is malformed");
  if (parseHeader(jwt).alg !== "EdDSA") throw new Error("JWT algorithm must be EdDSA");
  const document = await resolveDidVhDocument(did, sources, allowedDomainSuffix);
  if (!maySignIn(document, did, kid)) throw new Error("did:vh authentication method may not sign in");
  const rawKey = authenticationPublicKey(document, did, kid);
  const jwk: JsonWebKey = { kty: "OKP", crv: "Ed25519", x: Buffer.from(rawKey).toString("base64url") };
  let key: CryptoKey;
  try { key = await crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, ["verify"]); }
  catch { throw new Error("resolved did:vh authentication key is invalid"); }
  const valid = await crypto.subtle.verify({ name: "Ed25519" }, key, decodePart(parts[2]!, "JWT signature"), new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
  if (!valid) throw new Error("JWT signature is invalid");
  return { sub: did, method: "did-vh", publicKeyJwk: jwk };
}

export async function verifyIdTokenSignature(jwt: string, allowedDomainSuffix?: string, vh?: VhSources): Promise<VerifiedSigner> {
  const header = parseHeader(jwt);
  if (header.jwk && typeof header.jwk === "object" && !Array.isArray(header.jwk)) return verifyViaEmbeddedJwk(jwt, header.jwk as JsonWebKey);
  if (typeof header.kid === "string" && header.kid.startsWith("did:webvh:")) return verifyViaDidWebvh(jwt, header.kid, allowedDomainSuffix);
  if (typeof header.kid === "string" && header.kid.startsWith("did:vh:")) {
    if (!vh) throw new Error("a did:vh signer needs a verifier with watchers to get its log from");
    return verifyViaDidVh(jwt, header.kid, vh, allowedDomainSuffix);
  }
  throw new Error("jwk header missing and no other verification method available");
}
