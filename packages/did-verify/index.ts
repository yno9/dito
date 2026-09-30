import { authenticationPublicKey, parseDid, resolveDidWebvh } from "../webvh/src/index.ts";

export interface VerifiedSigner {
  sub: string;
  method: "jwk" | "did-webvh";
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

async function resolveDidWebvhAuthenticationKey(did: string, verificationMethod: string): Promise<Uint8Array> {
  return authenticationPublicKey(await resolveDidWebvhDocument(did), did, verificationMethod);
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
  const rawKey = await resolveDidWebvhAuthenticationKey(did, kid);
  const jwk: JsonWebKey = { kty: "OKP", crv: "Ed25519", x: Buffer.from(rawKey).toString("base64url") };
  let key: CryptoKey;
  try { key = await crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, ["verify"]); }
  catch { throw new Error("resolved did:webvh authentication key is invalid"); }
  const valid = await crypto.subtle.verify({ name: "Ed25519" }, key, decodePart(parts[2]!, "JWT signature"), new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
  if (!valid) throw new Error("JWT signature is invalid");
  return { sub: did, method: "did-webvh", publicKeyJwk: jwk };
}

export async function verifyIdTokenSignature(jwt: string, allowedDomainSuffix?: string): Promise<VerifiedSigner> {
  const header = parseHeader(jwt);
  if (header.jwk && typeof header.jwk === "object" && !Array.isArray(header.jwk)) return verifyViaEmbeddedJwk(jwt, header.jwk as JsonWebKey);
  if (typeof header.kid === "string" && header.kid.startsWith("did:webvh:")) return verifyViaDidWebvh(jwt, header.kid, allowedDomainSuffix);
  throw new Error("jwk header missing and no other verification method available");
}
