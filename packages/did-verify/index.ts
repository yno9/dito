import { InMemoryVersionMemory, authenticationPublicKey, maySignIn, parseVhDid, resolveVhFromWatchers, type VersionMemory } from "../vh/src/index.ts";

export interface VerifiedSigner {
  sub: string;
  method: "jwk" | "did-vh";
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

// A resolved document's own freshness window: short enough that a key
// rotation is still visible almost immediately, long enough to absorb the
// network round trip's cost when the *same* DID is resolved again within a
// few seconds -- e.g. an OID4VP direct_post approval, then whatever
// downstream request re-verifies the same wallet's signature a moment
// later. Not a general-purpose HTTP cache: only resolveDidVhDocument's
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

/**
 * The subject an OIDC relying party should key an account on. A did:vh DID is its SCID already (it names no
 * location, so nothing in it moves) and is returned as it is; so is a JWK thumbprint.
 */
export function stableSubject(sub: string): string {
  return sub;
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
  parseVhDid(did);
  // The cache holds what was verified, not what was allowed: the issuer-domain rule applies to a cached document too.
  const document = cachedDidDocument(did) ?? await fetchDidVhDocument(did, sources);
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

async function fetchDidVhDocument(did: string, sources: VhSources): Promise<Record<string, unknown>> {
  const resolved = await resolveVhFromWatchers(did, { watchers: sources.watchers, fetch: sources.fetch, memory: sources.memory ?? vhMemory });
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
  if (typeof header.kid === "string" && header.kid.startsWith("did:vh:")) {
    if (!vh) throw new Error("a did:vh signer needs a verifier with watchers to get its log from");
    return verifyViaDidVh(jwt, header.kid, vh, allowedDomainSuffix);
  }
  throw new Error("jwk header missing and no other verification method available");
}
