/**
 * did.md did:webvh v1.0 host.
 *
 * This is the essential, non-optional part of did.md: it publishes and
 * verifies did:webvh identities (did.jsonl/did.json/did-witness.json/
 * routing.json) and resolves/verifies signatures against a DID's own
 * published authentication key. It stores no controller secret: browsers
 * create and sign entries; this process only verifies and atomically
 * publishes valid public artefacts.
 *
 * ARC.md §3/§3.4 (2026-09-21 rewrite): an OAuth/OID4VP "authorization
 * server" is NOT part of what a did:webvh host, or a SIOPv2/OID4VP self-
 * issued wallet, fundamentally requires -- the canonical SIOPv2 shape has
 * no third-party authorization server at all (a wallet self-issues an
 * id_token straight back to the RP's own response_uri). did.md's
 * `oauth-server.ts` is a convenience layer added on top, for relying
 * parties that lack their own backend and for continued/refreshable
 * access -- it is a CONSUMER of this module (resolving/verifying against a
 * DID's published state), never the reverse. Splitting these into separate
 * files makes that dependency direction, and which half is essential, read
 * directly from the codebase instead of needing to be explained.
 */
import { mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { validateLogAt, MAX_ENTRIES, Invalid, isObj, asObj, own, onlyKeys, parseJsonl, serialise, parseWitnessFile, mirrorDocument, type Json, type Obj, type Entry, type WitnessFile } from "../../packages/wallet/src/webvh-core.ts";
import { didToLogUrl as webvhDidToLogUrl, maySignIn, parseDid as webvhParseDid, verifyDataIntegrityProof as verifyProof, verifyProofSignature } from "../../packages/webvh/src/index.ts";
import { multibaseDecode } from "didwebvh-ts";
import { fetchWithHost } from "../host-fetch.ts";
export { MAX_ENTRIES, Invalid, isObj, asObj, own, onlyKeys, parseJsonl, parseWitnessFile, type Json, type Obj, type Entry, type Proof, type WitnessFile } from "../../packages/wallet/src/webvh-core.ts";

// Small helpers this host (and oauth-server.ts) use around the did:webvh log.
// The did:webvh mechanics themselves live in packages/webvh (didwebvh-ts).
/** A malformed DID is a client error (400), not a server fault. */
function invalidOnError<T>(fn: () => T): T { try { return fn(); } catch (error) { throw new Invalid(error instanceof Error ? error.message : "invalid DID"); } }
export function parseDid(did: string) { return invalidOnError(() => webvhParseDid(did)); }
export function didToLogUrl(did: string) { return invalidOnError(() => webvhDidToLogUrl(did)); }
export async function sha256(value: string) { return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))); }
export function b58decode(value: string): Uint8Array { return invalidOnError(() => multibaseDecode(`z${value}`).bytes); }
export function strictTime(value: string) {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)$/.test(value) || Number.isNaN(Date.parse(value))) throw new Invalid("timestamp must be an ISO-8601 UTC timestamp");
  return Date.parse(value);
}
/** Request-shape check for a Data Integrity proof object (signature checked elsewhere). */
export function proofObject(value: unknown, label: string) {
  const proof = asObj(value, label); onlyKeys(proof, ["type", "cryptosuite", "proofPurpose", "verificationMethod", "proofValue", "created"], label);
  for (const key of ["type", "cryptosuite", "proofPurpose", "verificationMethod", "proofValue"] as const) if (typeof proof[key] !== "string") throw new Invalid(`${label}.${key} must be a string`);
  if (proof.created !== undefined) strictTime(proof.created as string);
  return proof as unknown as import("../../packages/wallet/src/webvh-core.ts").Proof;
}

// PLAN9: `process` does not exist on a Cloudflare Worker -- a bare
// `process.env` reference at module scope would throw before this module could
// even finish loading there, regardless of whether anything in this file
// actually calls FsIdentityStore (the only consumer of DATA_DIR) at runtime.
// Every value read through this is either FsIdentityStore-only (DATA_DIR,
// unused once a cloud-worker IdentityStore is installed) or has a default that
// is already the correct value for this same identity domain running anywhere
// else (IDENTITY_DOMAIN).
// Read via globalThis: this file is also type-checked under
// server/host/edge/tsconfig.json (Cloudflare Workers types only, no Node
// ambient types at all), where a bare `process` identifier does not type-check.
const env: Record<string, string | undefined> = (globalThis as { process?: { env: Record<string, string | undefined> } }).process?.env ?? {};
export const DATA_DIR = env.DATA_DIR ?? "./data";
export const IDENTITY_DOMAIN = (env.IDENTITY_DOMAIN ?? "did.md").toLowerCase();
export const MAX_LOG_BYTES = 16 << 20;
/** Public reads may be served from a CDN for this long (SPEC-webvh-hosting.md §2).
 * Reads are ~all the traffic and never need this host; only writes do. Browsers
 * still revalidate (max-age=0); a CDN in front (Cloudflare) keeps a copy. A
 * writer that needs its own write back at once appends `?_=<time>` (the client
 * does). 404s are not cached, so a fresh identity is visible immediately. */
export const PUBLIC_READ_CACHE_SECONDS = 30;
const PUBLIC_READ_CACHE_CONTROL = `public, max-age=0, s-maxage=${PUBLIC_READ_CACHE_SECONDS}`;
export const MAX_REQUEST_BYTES = 1 << 20;
export const MAX_WITNESS_BYTES = 4 << 20;
export const CORS_BASE = {
  "access-control-allow-methods": "GET, POST, PUT, DELETE, OPTIONS",
  "access-control-allow-headers": "authorization, content-type, dpop",
  "access-control-max-age": "86400",
  "x-content-type-options": "nosniff",
};
const locks = new Map<string, Promise<void>>();

function numberEnv(name: string, fallback: number) { const value = Number(env[name] ?? fallback); return Number.isSafeInteger(value) && value > 0 ? value : fallback; }
export const PORT = numberEnv("PORT", 8787);

/** Browser clients are deliberately limited to the Wallet.  The API never
 * uses cookies, but reflecting arbitrary origins here would make a future
 * credential-bearing endpoint dangerously easy to add. */
export function cors(request: Request) {
  const origin = request.headers.get("origin");
  // "null" is what a browser sends as Origin for a file:// page (the
  // single-file dist/index.html build is meant to be opened this way). This
  // API never uses cookies and every write is guarded by a client-supplied
  // signature (verifyProof/verifyAuthenticationProof), so CORS here is only
  // about which browser contexts may read a response — not an auth boundary
  // — making it safe to include file:// alongside the hosted origins.
  // isLoopbackDevelopmentOrigin lets the dev build (client/app.ts points
  // API at http://localhost:8787 when location.hostname is localhost) call
  // this host directly instead of every local run needing app.did.md's
  // origin -- previously defined but never actually wired in here, so
  // every local /v1/availability etc. request was silently CORS-blocked.
  let loopback = false;
  if (origin) { try { loopback = isLoopbackDevelopmentOrigin(new URL(origin)); } catch {} }
  const allowed = origin === "https://app.did.md" || origin === "https://client.did.md" || origin === "null" || loopback;
  return { ...CORS_BASE, ...(allowed ? { "access-control-allow-origin": origin } : {}) };
}
/** DID documents and did:webvh logs are public verification artefacts.  They
 * must be readable by a relying party that verifies a DID locally, including
 * an origin not known when this host was deployed.  This is intentionally
 * used only for GET responses from the public document routes. */
export function publicDocumentCors() { return { ...CORS_BASE, "access-control-allow-origin": "*" }; }
export function isLoopbackDevelopmentOrigin(parsed: URL) {
  return parsed.protocol === "http:" && (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1" || parsed.hostname === "[::1]");
}
export function isLocalFileRedirect(parsed: URL) { return parsed.protocol === "file:" && !parsed.host; }
export function json(request: Request, body: Json, status = 200) { return new Response(JSON.stringify(body), { status, headers: { ...cors(request), "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } }); }
export function text(request: Request, body: string, status: number) { return new Response(`${body}\n`, { status, headers: { ...cors(request), "content-type": "text/plain; charset=utf-8" } }); }
export function identityOrigin(username: string) { return `https://${username}.${IDENTITY_DOMAIN}`; }
function sameLocation(did: string, username: string) { return didToLogUrl(did) === `${identityOrigin(username)}/.well-known/did.jsonl`; }
export async function validateLog(entries: Entry[], witnessFile: WitnessFile, username: string, enforcePublicationLocation = true) {
  return validateLogAt(entries, witnessFile, enforcePublicationLocation ? `${identityOrigin(username)}/.well-known/did.jsonl` : undefined);
}

export function safeName(value: string, label: string) { if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(value)) throw new Invalid(`${label} must be a 1–63 character lowercase DNS-label-like identifier`); return value; }
export function basePath(username: string) { return join(DATA_DIR, "logs", safeName(username, "username")); }
export function read(path: string) { try { return readFileSync(path, "utf8"); } catch (error: any) { if (error?.code === "ENOENT") return null; throw error; } }
function removeIfExists(path: string) { try { unlinkSync(path); } catch (error: any) { if (error?.code !== "ENOENT") throw error; } }
export function atomicWrite(path: string, content: string) { mkdirSync(dirname(path), { recursive: true, mode: 0o700 }); const temporary = `${path}.${process.pid}.${crypto.randomUUID()}.tmp`; writeFileSync(temporary, content, { mode: 0o600 }); renameSync(temporary, path); }
export async function exclusive<T>(key: string, task: () => Promise<T>): Promise<T> { const before = locks.get(key) ?? Promise.resolve(); let release!: () => void; const after = new Promise<void>(resolve => { release = resolve; }); locks.set(key, before.then(() => after)); await before; try { return await task(); } finally { release(); if (locks.get(key) === after) locks.delete(key); } }

// PLAN9: the per-username
// did:webvh storage surface -- 4 named slots, read/write/remove, plus a
// per-username critical section -- pulled behind an interface so a cloud
// worker deployment (Durable-Object-backed, one DO per username, whose
// single-threaded execution model replaces `exclusive` outright) can
// implement it without this module knowing or caring. `read`/`atomicWrite`/
// `exclusive` above are UNCHANGED and stay exported as-is: oauth-server.ts
// uses them directly for its own, unrelated single-file state (DCR client
// registrations under a fixed "oauth" key, not a per-username slot) and has
// no reason to route through this abstraction.
export type IdentitySlot = "log" | "witness" | "web" | "routing";
const SLOT_FILENAME: Record<IdentitySlot, string> = { log: "did.jsonl", witness: "did-witness.json", web: "did.json", routing: "routing.json" };
export interface IdentityStore {
  read(username: string, slot: IdentitySlot): Promise<string | null>;
  write(username: string, slot: IdentitySlot, content: string): Promise<void>;
  remove(username: string, slot: IdentitySlot): Promise<void>;
  exclusive<T>(username: string, task: () => Promise<T>): Promise<T>;
}
// The VPS/Node default: identical behavior to what this module always did
// (same file layout, same in-process lock map), just reached through the
// interface instead of inline `join(basePath(username), "did.jsonl")` calls.
class FsIdentityStore implements IdentityStore {
  async read(username: string, slot: IdentitySlot): Promise<string | null> { return read(join(basePath(username), SLOT_FILENAME[slot])); }
  async write(username: string, slot: IdentitySlot, content: string): Promise<void> { atomicWrite(join(basePath(username), SLOT_FILENAME[slot]), content); }
  async remove(username: string, slot: IdentitySlot): Promise<void> { removeIfExists(join(basePath(username), SLOT_FILENAME[slot])); }
  exclusive<T>(username: string, task: () => Promise<T>): Promise<T> { return exclusive(username, task); }
}
let identityStore: IdentityStore = new FsIdentityStore();
/** Swaps the storage backend (e.g. a Durable-Object-backed store on a cloud
 * worker deployment). Not called anywhere yet -- the VPS/Node deployment
 * keeps the default FsIdentityStore; this is the seam a future backend
 * plugs into. */
export function setIdentityStore(store: IdentityStore): void { identityStore = store; }

export async function requestBody(request: Request, max: number) {
  const length = Number(request.headers.get("content-length") ?? 0); if (length > max) throw new Invalid("request body is too large");
  const body = await request.text(); if (new TextEncoder().encode(body).byteLength > max) throw new Invalid("request body is too large"); return body;
}
function resourceRoute(pathname: string) {
  // `routing.json` is a did:webvh DID Resource. The implicit `#files`
  // service maps a DID URL path `/routing.json` to this origin-root path;
  // `.well-known` is deliberately excluded by the method's transformation.
  if (pathname === "/routing.json") return "routing.json";
  // Keep the historical pre-#files location as an alias while
  // `/routing.json` remains the canonical did:webvh DID Resource URL.
  if (pathname === "/.well-known/routing.json") return "routing.json";
  // atproto handle resolution: plaintext account DID (did:web mirror).
  // Derived from the published log — not a writable resource.
  if (pathname === "/.well-known/atproto-did") return "atproto-did";
  const matched = /^\/\.well-known\/(did\.jsonl|did-witness\.json|did\.json)$/.exec(pathname);
  return matched?.[1] ?? null;
}
function usernameFor(request: Request) {
  const host = (request.headers.get("host") ?? "").split(":")[0]!.toLowerCase();
  const suffix = `.${IDENTITY_DOMAIN}`;
  if (!host.endsWith(suffix)) throw new Invalid("identity host is required");
  return safeName(host.slice(0, -suffix.length), "username");
}
const RESOURCE_SLOT: Record<string, IdentitySlot> = { "did.jsonl": "log", "did-witness.json": "witness", "did.json": "web", "routing.json": "routing" };
async function serveLog(request: Request, username: string, resource: string) {
  if (request.method === "GET") {
    if (resource === "atproto-did") {
      // atproto handle resolution reads a single plaintext account DID.
      // atproto only understands did:plc / did:web, so publish the parallel
      // did:web mirror of this did:webvh identity (not the webvh form).
      const logBody = await identityStore.read(username, "log");
      if (logBody === null) return new Response("not found\n", { status: 404, headers: { ...publicDocumentCors(), "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });
      const accountDid = `did:web:${username}.${IDENTITY_DOMAIN}`;
      return new Response(`${accountDid}\n`, { headers: { ...publicDocumentCors(), "content-type": "text/plain; charset=utf-8", "cache-control": PUBLIC_READ_CACHE_CONTROL } });
    }
    const body = await identityStore.read(username, RESOURCE_SLOT[resource]!);
    if (body === null) return new Response("not found\n", { status: 404, headers: { ...publicDocumentCors(), "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });
    const contentType = resource === "did.jsonl" ? "text/jsonl; charset=utf-8" : "application/json; charset=utf-8";
    return new Response(body, { headers: { ...publicDocumentCors(), "content-type": contentType, "cache-control": resource === "routing.json" ? "no-store" : PUBLIC_READ_CACHE_CONTROL } });
  }
  if (resource === "atproto-did") return text(request, "method not allowed", 405);
  if (resource === "did.json") return text(request, "did.json is derived from did.jsonl and cannot be written directly", 405);
  if (resource === "routing.json") {
    if (request.method !== "PUT") return text(request, "method not allowed", 405);
    return identityStore.exclusive(username, async () => {
      // This DID Resource is intentionally outside the did:webvh event log:
      // it holds mutable service discovery metadata, not DID controller state.
      // It still must be authenticated by the current Sign/update key.  The
      // proof is transport-only and is never served back as routing data.
      const incoming = asObj(JSON.parse(await requestBody(request, MAX_REQUEST_BYTES)), "routing document");
      const proof = proofObject(incoming.proof, "routing document.proof");
      const document: Obj = { ...incoming }; delete document.proof;
      const source = await identityStore.read(username, "log"); if (source === null) throw new Invalid("routing.json requires a published did.jsonl");
      const witnesses = await identityStore.read(username, "witness"); const witness = witnesses === null ? [] : parseWitnessFile(witnesses);
      const checked = await validateLog(parseJsonl(source), witness, username);
      if (!(await verifyProof(document, proof, checked.parameters.updateKeys))) throw new Invalid("routing.json has no valid current update-key proof");
      await identityStore.write(username, "routing", `${JSON.stringify(document)}\n`);
      return new Response(null, { status: 204, headers: cors(request) });
    });
  }
  if (request.method === "DELETE") {
    // "Disconnect": remove this identity's published files from this host.
    // The did:webvh spec explicitly permits removing the published DID Log
    // as a way to signal deactivation, so this is not purely cosmetic --
    // resolvers will see a 404 until the same controller republishes here.
    if (resource !== "did.jsonl") return text(request, "method not allowed", 405);
    return identityStore.exclusive(username, async () => {
      const source = await identityStore.read(username, "log"); if (source === null) return text(request, "not found", 404);
      const witnesses = await identityStore.read(username, "witness"); const witness = witnesses === null ? [] : parseWitnessFile(witnesses);
      const checked = await validateLog(parseJsonl(source), witness, username);
      const incoming = asObj(JSON.parse(await requestBody(request, MAX_REQUEST_BYTES)), "disconnect request");
      const proof = proofObject(incoming.proof, "disconnect request.proof");
      const document: Obj = { ...incoming }; delete document.proof;
      if (document.did !== checked.latest.state.id) throw new Invalid("disconnect request.did does not match the published DID");
      if (typeof proof.created !== "string") throw new Invalid("disconnect request.proof.created is required");
      const created = Date.parse(proof.created);
      if (Number.isNaN(created) || Math.abs(Date.now() - created) > 5 * 60_000) throw new Invalid("disconnect proof is outside its accepted time window");
      if (!(await verifyProof(document, proof, checked.parameters.updateKeys))) throw new Invalid("disconnect request has no valid current update-key proof");
      for (const slot of ["log", "witness", "web", "routing"] as const) await identityStore.remove(username, slot);
      return new Response(null, { status: 204, headers: cors(request) });
    });
  }
  if (request.method !== "PUT" && !(resource === "did.jsonl" && request.method === "POST")) return text(request, "method not allowed", 405);
  return identityStore.exclusive(username, async () => {
    if (resource === "did-witness.json") {
      const body = await requestBody(request, MAX_WITNESS_BYTES); const witness = parseWitnessFile(body);
      const existingLog = await identityStore.read(username, "log");
      // Future proofs are intentionally accepted before publishing the entry;
      // when a current log exists it must remain valid after this replacement.
      if (existingLog !== null) await validateLog(parseJsonl(existingLog), witness, username);
      await identityStore.write(username, "witness", JSON.stringify(witness));
      return new Response(null, { status: 204, headers: cors(request) });
    }
    // A complete portable history may be up to the log limit.  Ordinary JSON
    // resources remain limited to 1 MiB.
    const incoming = parseJsonl(await requestBody(request, resource === "did.jsonl" ? MAX_LOG_BYTES : MAX_REQUEST_BYTES));
    const existingText = await identityStore.read(username, "log"); const existing = existingText === null ? [] : parseJsonl(existingText);
    let combined: Entry[];
    if (request.method === "POST") {
      if (!existing.length) throw new Invalid("POST requires an existing log; publish genesis with PUT");
      if (own(incoming[0]!.parameters, "scid")) throw new Invalid("POST contains a genesis entry; use PUT only for a full log");
      combined = [...existing, ...incoming];
    } else {
      if (existing.length) {
        const prior = serialise(existing); const candidate = serialise(incoming);
        if (!candidate.startsWith(prior)) throw new Invalid("PUT must preserve the existing log as a byte-for-byte prefix");
      }
      combined = incoming;
    }
    const full = serialise(combined); if (new TextEncoder().encode(full).byteLength > MAX_LOG_BYTES) throw new Invalid("log exceeds its 16 MiB limit");
    const witnesses = await identityStore.read(username, "witness"); const witness = witnesses === null ? [] : parseWitnessFile(witnesses);
    const checked = await validateLog(combined, witness, username);
    await identityStore.write(username, "log", full);
    await identityStore.write(username, "web", `${JSON.stringify(mirrorDocument(checked.latest.state, checked.latest.state.id as string))}\n`);
    return new Response(null, { status: existing.length ? 204 : 201, headers: cors(request) });
  });
}

// ── Wallet identity verification: resolving/verifying signatures against a
// DID's own published authentication key. Genuinely an identity concern
// (not OAuth): both did.md's own oauth-server.ts and any independent third
// party can (and, for a self-issued id_token, are expected to) perform this
// same resolution themselves -- see verifySelfIssuedIdToken's own comment.
export const AUTH_PROOF_CLOCK_SKEW_MS = 5 * 60_000;
export function b64url(bytes: Uint8Array) { return Buffer.from(bytes).toString("base64url"); }
export function b64urlBytes(value: string) {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw new Invalid("invalid base64url value");
  const decoded = new Uint8Array(Buffer.from(value, "base64url"));
  if (!decoded.length && value) throw new Invalid("invalid base64url value");
  return decoded;
}
export async function sha256B64url(value: string) { return b64url(await sha256(value)); }
export function randomB64url(bytes = 32) { return b64url(crypto.getRandomValues(new Uint8Array(bytes))); }
export function isoAt(value: number) { return new Date(value).toISOString(); }
export function strictObjectKeys(value: Obj, keys: string[], label: string) {
  const found = Object.keys(value).sort().join(","); const expected = [...keys].sort().join(",");
  if (found !== expected) throw new Invalid(`${label} has unexpected fields`);
}
export function opaqueId(value: Json | undefined, label: string) {
  if (typeof value !== "string" || !/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) throw new Invalid(`${label} must be a UUID URN`);
  return value;
}
export function validTime(value: Json | undefined, label: string) { if (typeof value !== "string") throw new Invalid(`${label} must be a timestamp`); strictTime(value); return value; }
// PLAN1: Identity-layer key
// resolution no longer assumes a fixed "#pass-1" fragment or an Ed25519-only
// key. A caller that already knows which key a proof/id_token claims (via
// its own verificationMethod/kid) resolves exactly that one; the multikey
// decode and cryptosuite/alg checks are dispatched by key type so a future
// non-Ed25519 authentication method fails loudly instead of silently
// mis-decoding. Only Ed25519 is implemented today -- this is a dispatch
// point, not a claim that other key types work.
export type AuthenticationKeyType = "Ed25519";
export type AuthenticationAuthority = { did: string; verificationMethod: string; keyType: AuthenticationKeyType; key: Uint8Array };
// Decodes a multikey from a DID Document's own verificationMethod entries
// (authentication, assertionMethod, ...). This is distinct from publicKey(),
// which decodes DID *log* control keys (updateKeys/witnesses) under
// did.md's log-signing policy -- did:webvh:1.0 itself does not constrain a
// published DID Document's verificationMethod to any particular key type
// (ordinary DID Core "multikey" content), so this decoder is free to grow
// beyond Ed25519 without touching log verification at all.
function authenticationMultikey(multikey: string, label: string): { keyType: AuthenticationKeyType; key: Uint8Array } {
  if (!multikey.startsWith("z")) throw new Invalid(`${label} must use base58btc`);
  const bytes = b58decode(multikey.slice(1));
  if (bytes.length === 34 && bytes[0] === 0xed && bytes[1] === 0x01) return { keyType: "Ed25519", key: bytes.slice(2) };
  throw new Invalid(`${label} uses an unsupported key type (only Ed25519 is implemented)`);
}
export function cryptosuiteForKeyType(keyType: AuthenticationKeyType): string {
  switch (keyType) { case "Ed25519": return "eddsa-jcs-2022"; default: throw new Invalid("unsupported authentication key type"); }
}
export function jwtAlgForKeyType(keyType: AuthenticationKeyType): string {
  switch (keyType) { case "Ed25519": return "EdDSA"; default: throw new Invalid("unsupported authentication key type"); }
}
// PLAN10: resolves over HTTPS, not
// identityStore (a VPS-local FsIdentityStore snapshot) -- PLAN9 moved
// did.md's own did:webvh CRUD to a Cloudflare Worker + Durable Object in
// production, so identityStore's local copy is a frozen point-in-time
// snapshot from the migration, not a live source of truth, for any
// identity created or updated since. Full chain validation (validateLog)
// is kept, unlike the lighter resolveDidWebvhDocument (packages/did-verify)
// external RPs get -- did.md's own hosted identities get the same
// verification strength this always had, just fetched instead of read
// locally.
// Test-only escape hatch: a spawned test server has no real internet-
// routable domain for its fabricated identities (they publish under a
// spoofed `host: <username>.did.md` header against `http://127.0.0.1:PORT`,
// same as identityFetch's own usernameFor already relies on for every other
// route). Unset in production -- hostedAuthenticationKey then always
// resolves the real public domain, as it must now that identity data lives
// on the Cloudflare Worker (PLAN9), not this process.
const IDENTITY_FETCH_BASE_URL = env.IDENTITY_FETCH_BASE_URL;
export async function hostedAuthenticationKey(did: string, expectedVerificationMethod?: string) {
  const parsed = parseDid(did);
  const suffix = `.${IDENTITY_DOMAIN}`;
  if (parsed.port || parsed.segments.length || !parsed.domain.endsWith(suffix)) throw new Invalid("authenticated issuer must be a hosted did.md identity");
  const username = safeName(parsed.domain.slice(0, -suffix.length), "authenticated issuer");
  const origin = IDENTITY_FETCH_BASE_URL ?? `https://${parsed.domain}`;
  const fetchInit = IDENTITY_FETCH_BASE_URL ? { headers: { host: parsed.domain } } : undefined;
  const logResponse = await fetchWithHost(`${origin}/.well-known/did.jsonl`, fetchInit);
  if (!logResponse.ok) throw new Invalid("authenticated issuer was not found");
  const source = await logResponse.text();
  const entries = parseJsonl(source);
  // The witness file only matters when the log configures witnesses; asking for
  // it unconditionally doubled the requests every verification sent to the host.
  const usesWitnesses = entries.some(entry => Array.isArray((entry.parameters.witness as { witnesses?: unknown } | undefined)?.witnesses) && ((entry.parameters.witness as { witnesses: unknown[] }).witnesses.length > 0));
  let witnesses: string | null = null;
  if (usesWitnesses) {
    const witnessResponse = await fetchWithHost(`${origin}/.well-known/did-witness.json`, fetchInit);
    witnesses = witnessResponse.ok ? await witnessResponse.text() : null;
  }
  const checked = await validateLog(entries, witnesses === null ? [] : parseWitnessFile(witnesses), username);
  if (checked.latest.state.id !== did) throw new Invalid("authenticated issuer does not match its current DID document");
  return authenticationKeyFromState(did, checked.latest.state, expectedVerificationMethod);
}
// Resolves an `authentication` verification method from a DID Document
// state. When `expectedVerificationMethod` is supplied (a proof's own
// verificationMethod, or an id_token's own kid), exactly that entry is
// resolved -- no fragment name (e.g. "#pass-1") is assumed. When omitted,
// there must be exactly one authentication method (an ambiguous document is
// rejected rather than guessing). Only a method that may sign the user in
// counts (maySignIn: on a did.md identity, its Root key alone).
export function authenticationKeyFromState(did: string, state: Obj, expectedVerificationMethod?: string): AuthenticationAuthority {
  const methods = Array.isArray(state.verificationMethod) ? state.verificationMethod : [];
  const authentication = Array.isArray(state.authentication) ? state.authentication : [];
  const wantedAbsolute = expectedVerificationMethod === undefined ? undefined
    : expectedVerificationMethod.startsWith("#") ? `${did}${expectedVerificationMethod}` : expectedVerificationMethod;
  const candidates = methods.filter((value): value is Obj => {
    if (!isObj(value) || typeof value.id !== "string") return false;
    const absolute = value.id.startsWith("#") ? `${did}${value.id}` : value.id;
    const relative = value.id.startsWith("#") ? value.id : undefined;
    if (!authentication.includes(absolute) && !(relative !== undefined && authentication.includes(relative))) return false;
    return (wantedAbsolute === undefined || absolute === wantedAbsolute) && maySignIn(state, did, absolute);
  });
  if (candidates.length !== 1) throw new Invalid(wantedAbsolute === undefined ? "authenticated issuer has no unambiguous authentication method" : "authenticated issuer has no matching authentication method");
  const method = candidates[0]!;
  if (typeof method.publicKeyMultibase !== "string") throw new Invalid("authenticated issuer has no Root authentication method");
  const methodId = method.id as string;
  const vmId = methodId.startsWith("#") ? `${did}${methodId}` : methodId;
  const { keyType, key } = authenticationMultikey(method.publicKeyMultibase, "authentication verificationMethod");
  return { did, verificationMethod: vmId, keyType, key };
}
export async function verifyAuthenticationProof(document: Obj, proofValue: Json | undefined, issuer: string, maxAgeMs: number, suppliedAuthority?: AuthenticationAuthority) {
  const proof = proofObject(proofValue, "Wallet proof");
  const authority = suppliedAuthority ?? await hostedAuthenticationKey(issuer, proof.verificationMethod);
  if (proof.type !== "DataIntegrityProof" || proof.cryptosuite !== cryptosuiteForKeyType(authority.keyType) || proof.proofPurpose !== "authentication" || proof.verificationMethod !== authority.verificationMethod || !proof.proofValue.startsWith("z")) throw new Invalid("Wallet proof is not an authorized authentication proof");
  if (proof.created) {
    const created = Date.parse(proof.created);
    if (created > Date.now() + AUTH_PROOF_CLOCK_SKEW_MS || Date.now() - created > maxAgeMs) throw new Invalid("Wallet proof is outside its accepted time window");
  }
  if (!await verifyProofSignature(document, proof, authority.key)) throw new Invalid("Wallet proof signature is invalid");
}

// Verifies a Wallet-self-issued id_token (see createSelfIssuedIdToken in
// client/did-webvh.ts): a JWT signed with the DID's own authentication key,
// never with any key this server holds. This server only sanity-checks it
// before handing it to a relying party (defense in depth); the relying
// party is expected to independently resolve `kid` and verify it too --
// that independent verifiability, not this check, is the point of a
// self-issued token. The `kid` fragment (e.g. "#pass-1") is not assumed --
// whatever the token claims is resolved against the DID's own authentication
// array (see authenticationKeyFromState).
export async function verifySelfIssuedIdToken(idToken: string, expectedIssuer: string, expectedAudience: string, maxAgeMs: number, suppliedAuthority?: AuthenticationAuthority) {
  const parts = idToken.split("."); if (parts.length !== 3) throw new Invalid("id_token is malformed");
  let header: Obj; let payload: Obj; let signature: Uint8Array;
  try { header = asObj(JSON.parse(new TextDecoder().decode(b64urlBytes(parts[0]!))), "id_token header"); payload = asObj(JSON.parse(new TextDecoder().decode(b64urlBytes(parts[1]!))), "id_token payload"); signature = b64urlBytes(parts[2]!); }
  catch (error) { if (error instanceof Invalid) throw error; throw new Invalid("id_token is malformed"); }
  if (typeof header.kid !== "string" || !header.kid.startsWith(`${expectedIssuer}#`) || header.typ !== "JWT") throw new Invalid("id_token header is invalid");
  if (
    payload.iss !== expectedIssuer ||
    (payload.sub !== expectedIssuer && payload.sub !== payload.iss) ||
    payload.aud !== expectedAudience
  ) {
    // SIOPv2: identity DID lives in `iss`. Accept `sub === iss` even when a
    // client mistakenly puts a JWK thumbprint in `sub` — but only if iss
    // still matches this authorization (capability issuer).
    const subOk =
      payload.sub === expectedIssuer ||
      (payload.iss === expectedIssuer && payload.sub === payload.iss)
    if (!(payload.iss === expectedIssuer && subOk && payload.aud === expectedAudience)) {
      console.error(JSON.stringify({
        event: "id_token.claims_mismatch",
        expectedIssuer,
        expectedAudience,
        iss: payload.iss,
        sub: payload.sub,
        aud: payload.aud,
        kid: header.kid,
      }))
      throw new Invalid("id_token claims do not match this authorization")
    }
  }
  if (!Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp)) throw new Invalid("id_token timestamps are invalid");
  const now = Date.now();
  if (Number(payload.iat) * 1000 > now + AUTH_PROOF_CLOCK_SKEW_MS || now - Number(payload.iat) * 1000 > maxAgeMs || Number(payload.exp) * 1000 <= now) throw new Invalid("id_token is outside its accepted time window");
  if (signature.length !== 64) throw new Invalid("id_token signature is invalid");
  const authority = suppliedAuthority ?? await hostedAuthenticationKey(expectedIssuer, header.kid);
  if (authority.verificationMethod !== header.kid) throw new Invalid("id_token key does not match the authenticated issuer");
  if (header.alg !== jwtAlgForKeyType(authority.keyType)) throw new Invalid("id_token header is invalid");
  try {
    const imported = await crypto.subtle.importKey("raw", authority.key, { name: authority.keyType }, false, ["verify"]);
    if (!await crypto.subtle.verify({ name: authority.keyType }, imported, signature, new TextEncoder().encode(`${parts[0]}.${parts[1]}`))) throw new Error();
  } catch { throw new Invalid("id_token signature is invalid"); }
  return payload;
}

/** Every non-OAuth route this host serves: did:webvh log CRUD,
 * computation, username availability. Returns undefined for any path it
 * does not own, so the caller (server.ts) can fall through to oauth-server.ts. */
export async function identityFetch(request: Request, url: URL): Promise<Response | undefined> {
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: resourceRoute(url.pathname) ? publicDocumentCors() : cors(request) });
  }
  if (url.pathname === "/v1/availability" && request.method === "GET") {
    const username = safeName(url.searchParams.get("username") ?? "", "username");
    return json(request, { available: (await identityStore.read(username, "log")) === null, didLog: `${identityOrigin(username)}/.well-known/did.jsonl` });
  }
  // did:webvh Hosting Protocol capability document (SPEC-webvh-hosting.md §5):
  // lets a client tell "this host speaks the protocol" from "unknown".
  if (url.pathname === "/.well-known/did-hosting.json" && request.method === "GET") {
    return new Response(`${JSON.stringify({ protocol: "webvh-hosting/1", writes: true, delete: true, witness: true, maxLogBytes: MAX_LOG_BYTES })}\n`, {
      headers: { ...publicDocumentCors(), "content-type": "application/json; charset=utf-8", "cache-control": "no-cache" },
    });
  }
  const resource = resourceRoute(url.pathname);
  if (!resource) return undefined;
  // Protocol resources: authorization is the log's own validity, never the
  // caller's origin or a cookie (SPEC §4), so reads, writes AND errors are
  // readable from any origin -- a third-party browser wallet must work.
  if (resource === "did.jsonl" || resource === "did-witness.json") {
    let response: Response;
    try { response = await serveLog(request, usernameFor(request), resource); }
    catch (error) { if (!(error instanceof Invalid)) throw error; response = text(request, error.message, 400); }
    const headers = new Headers(response.headers);
    for (const [name, value] of Object.entries(publicDocumentCors())) headers.set(name, value);
    return new Response(response.body, { status: response.status, headers });
  }
  return await serveLog(request, usernameFor(request), resource);
}
