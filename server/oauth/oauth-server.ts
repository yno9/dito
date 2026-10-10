/**
 * did.md OAuth 2.0 / OID4VP authorization server.
 *
 * NOT essential to did.md or to SIOPv2/OID4VP: the canonical self-issued
 * flow has no third-party authorization server at all (a wallet redirects
 * straight back to the RP's own response_uri with response_mode=direct_post
 * and the RP verifies the self-issued id_token/vp_token itself, resolving
 * the wallet's DID exactly as identity-host.ts's own verifySelfIssuedIdToken
 * does). This module exists as a convenience layer for two things a bare
 * self-issued token doesn't provide on its own: (1) a safe way for a
 * relying party that has no backend of its own (a browser-only RP) to
 * receive a token without exposing it raw in a redirect URL, via a
 * short-lived `code`; (2) continued, refreshable access without re-
 * prompting the user every time, via DPoP-bound access tokens.
 *
 * Every function here is a CONSUMER of identity-host.ts (resolving/
 * verifying against a DID's published state), never the reverse -- see
 * ARC.md §3/§3.4 for the full reasoning this split makes structural.
 */
import { join } from "node:path";
import { parseWebvhDid, resolveDidWebvhDocument } from "../../packages/did-verify/index.ts";
import {
  AUTH_PROOF_CLOCK_SKEW_MS, CORS_BASE, DATA_DIR, Invalid,
  asObj, atomicWrite, authenticationKeyFromState, b64url, b64urlBytes,
  exclusive, hostedAuthenticationKey, isLoopbackDevelopmentOrigin, isLocalFileRedirect,
  isObj, isoAt, onlyKeys, opaqueId, own, parseDid, parseJsonl, read, requestBody,
  sha256, sha256B64url, strictObjectKeys, validateLog, validTime, verifyAuthenticationProof,
  verifySelfIssuedIdToken,
  type AuthenticationAuthority, type Json, type Obj,
} from "../host/identity-host.ts";

function randomB64url(bytes = 32) { return b64url(crypto.getRandomValues(new Uint8Array(bytes))); }

// ── PLAN6: SSRF guard for did:webvh-authenticated (JAR) clients ────────────
// A did:webvh-authenticated relying party's client_id names an arbitrary
// domain, resolved by an unauthenticated caller of a public endpoint
// (oauthAuthorizeComplete) -- without a bound, that is an SSRF primitive
// letting anyone make this server fetch any HTTPS host it can reach
// (internal services, cloud metadata endpoints, ...). Fail closed:
// DID-scheme clients are accepted only from domains an operator explicitly
// lists here (comma-separated suffixes, e.g. "biset.md,oidc-bridge.did.md").
// Empty (the default) disables the DID-scheme path entirely -- every
// deployment that has not provisioned an RP DID (see
// scripts/create-rp-did.ts) keeps the DCR-only behavior it always had.
const OAUTH_DID_RP_DOMAINS = (process.env.OAUTH_DID_RP_DOMAINS ?? "").toLowerCase().split(",").map(value => value.trim()).filter(Boolean);
function oauthDidClientDomainAllowed(did: string): boolean {
  let domain: string;
  try { domain = parseWebvhDid(did).domain; } catch { return false; }
  return OAUTH_DID_RP_DOMAINS.some(suffix => domain === suffix || domain.endsWith(`.${suffix}`));
}

/** Dynamic client registration is intentionally available to arbitrary HTTPS
 * browser origins, loopback HTTP for local development, and the packaged
 * local file:// clients. Its management operations still require the per-client
 * registration access token, so reflecting an origin does not grant access
 * to another client's configuration. */
export function oauthCors(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin) return { ...CORS_BASE };
  if (origin === "null") return { ...CORS_BASE, "access-control-allow-origin": origin, vary: "origin" };
  try {
    const parsed = new URL(origin);
    if ((parsed.protocol !== "https:" && !isLoopbackDevelopmentOrigin(parsed)) || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) return { ...CORS_BASE };
    return { ...CORS_BASE, "access-control-allow-origin": origin, vary: "origin" };
  } catch { return { ...CORS_BASE }; }
}
export function oauthJson(request: Request, body: Json, status = 200, headers: Record<string, string> = {}) { return new Response(JSON.stringify(body), { status, headers: { ...oauthCors(request), ...headers, "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } }); }

// ── Wallet authorization: DPoP proof verification (RFC 9449) ───────────────
const MAX_DPOP_REPLAY_RECORDS = 100_000;
type P256Jwk = { kty: "EC"; crv: "P-256"; x: string; y: string };
const dpopReplay = new Map<string, number>();
function p256Jwk(value: Json | undefined, label: string): P256Jwk {
  const input = asObj(value, label); strictObjectKeys(input, ["crv", "kty", "x", "y"], label);
  if (input.kty !== "EC" || input.crv !== "P-256" || typeof input.x !== "string" || typeof input.y !== "string") throw new Invalid(`${label} must be a P-256 public JWK`);
  if (b64urlBytes(input.x).length !== 32 || b64urlBytes(input.y).length !== 32) throw new Invalid(`${label} must contain 32-byte coordinates`);
  return { kty: "EC", crv: "P-256", x: input.x, y: input.y };
}
async function p256Jkt(key: P256Jwk) { return sha256B64url(JSON.stringify({ crv: key.crv, kty: key.kty, x: key.x, y: key.y })); }
async function verifyP256Dpop(value: string, request: Request, expectedUrl: string, requiredNonce?: string): Promise<{ key: P256Jwk; jkt: string }> {
  const parts = value.split("."); if (parts.length !== 3) throw new Invalid("DPoP proof is malformed");
  let header: Obj; let payload: Obj; let signature: Uint8Array;
  try { header = asObj(JSON.parse(new TextDecoder().decode(b64urlBytes(parts[0]!))), "DPoP header"); payload = asObj(JSON.parse(new TextDecoder().decode(b64urlBytes(parts[1]!))), "DPoP payload"); signature = b64urlBytes(parts[2]!); }
  catch (error) { if (error instanceof Invalid) throw error; throw new Invalid("DPoP proof is malformed"); }
  strictObjectKeys(header, ["alg", "jwk", "typ"], "DPoP header");
  if (header.alg !== "ES256" || header.typ !== "dpop+jwt") throw new Invalid("DPoP proof uses an unsupported algorithm");
  const key = p256Jwk(header.jwk, "DPoP JWK");
  if (payload.htm !== request.method || payload.htu !== expectedUrl || typeof payload.jti !== "string" || !/^[A-Za-z0-9_-]{20,128}$/.test(payload.jti) || !Number.isSafeInteger(payload.iat)) throw new Invalid("DPoP proof does not bind this request");
  if (requiredNonce !== undefined && payload.nonce !== requiredNonce) throw new Invalid("DPoP nonce is invalid");
  const now = Date.now();
  if (Math.abs(now - Number(payload.iat) * 1000) > AUTH_PROOF_CLOCK_SKEW_MS) throw new Invalid("DPoP proof is outside its accepted time window");
  for (const [key, expiresAt] of dpopReplay) if (expiresAt <= now) dpopReplay.delete(key);
  const replayKey = `${await p256Jkt(key)}:${payload.jti}`;
  if (dpopReplay.has(replayKey)) throw new Invalid("DPoP proof was replayed");
  if (dpopReplay.size >= MAX_DPOP_REPLAY_RECORDS) throw new Invalid("DPoP replay cache is at capacity; try again shortly");
  if (signature.length !== 64) throw new Invalid("DPoP signature is invalid");
  try {
    const imported = await crypto.subtle.importKey("jwk", key, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const valid = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, imported, signature, new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
    if (!valid) throw new Error();
  } catch { throw new Invalid("DPoP signature is invalid"); }
  dpopReplay.set(replayKey, now + AUTH_PROOF_CLOCK_SKEW_MS);
  return { key, jkt: await p256Jkt(key) };
}

// ── OAuth Authorization Server / Dynamic Client Registration ────────────
//
// This is the production-shaped OAuth public-client flow. The server stores
// registration metadata and opaque hashes only; the Wallet browser supplies
// Root-authenticated public capability proofs at authorization time.
const PUBLIC_API_ORIGIN = (process.env.PUBLIC_API_ORIGIN ?? "https://api.did.md").replace(/\/$/, "");
const OAUTH_ISSUER = PUBLIC_API_ORIGIN;
const OAUTH_CODE_MS = 5 * 60_000;
const OAUTH_TOKEN_MS = 15 * 60_000;
const OAUTH_CAPABILITY_MAX_MS = 31 * 24 * 60 * 60_000;
const OAUTH_MAX_CLIENTS = 10_000;
const OAUTH_MAX_REDIRECTS = 8;
const OAUTH_MAX_SCOPES = 16;
const OAUTH_REGISTRATION_WINDOW_MS = 60 * 60_000;
const OAUTH_MAX_REGISTRATIONS_PER_WINDOW = 20;
type OAuthClient = {
  clientId: string; clientName: string; redirectUris: string[]; scopes: string[];
  createdAt: string; updatedAt: string; registrationTokenHash: string;
  // Opt-in: the RP reports success/failure back via POST /v1/oauth/outcome. Absent in older persisted clients (= false).
  outcomeReporting?: boolean;
};
// PLAN3: the capability is now a
// VC-DM 2.0 Verifiable Credential with an embedded `proof`, not a
// `{document, proof}` sibling pair. OAuthCapability names "the whole VC
// object" -- see verifiedOauthCapability for its required shape.
type OAuthCapability = Obj;
type OAuthCode = {
  clientId: string; redirectUri: string; did: string; capability: OAuthCapability;
  // deviceJkt is only present for DPoP-bound clients (see verifiedOauthCapability) --
  // a non-DPoP client (a conventional OIDC relying party like Forgejo) has none.
  capabilityId: string; deviceJkt?: string; scope: string[]; codeChallenge: string; expiresAt: string;
  // The Wallet's own self-issued id_token (EdDSA, signed with the DID's own
  // #pass-1 key -- see createSelfIssuedIdToken in client/did-webvh.ts), present
  // only when "openid" was requested. Passed through verbatim at the token
  // endpoint; this server never signs an id_token itself.
  idToken?: string;
  // Present only for a not-yet-published ("un-hatched") DID -- carried
  // through to the token endpoint so its re-verification of the stored
  // capability (defense in depth) can derive the same suppliedAuthority
  // again, instead of failing to resolve a did.jsonl that doesn't exist yet.
  didLog?: string;
};
type OAuthToken = { capabilityId: string; did: string; audience: string; deviceJkt?: string; scope: string[]; clientId: string; expiresAt: string; nonce?: string };
// Client registrations are a long-lived registry (any relying party may
// register), so they alone are persisted to disk. Authorization codes and
// access tokens are short-lived and unrevocable by design, so they live
// only in memory for this process.
type OAuthState = { clients: Record<string, OAuthClient> };
const oauthRegistrationRates = new Map<string, { count: number; resetAt: number }>();
const oauthCodes = new Map<string, OAuthCode>();
const oauthTokens = new Map<string, OAuthToken>();
// A file:// client cannot always retain window.opener (notably Safari).  Its
// high-entropy OAuth state is therefore a short-lived delivery handle.  The
// delivered code remains bound to both PKCE and the client's DPoP key.
const oauthFileCallbacks = new Map<string, { clientId: string; code: string; expiresAt: string }>();

function oauthPath() { return join(DATA_DIR, "oauth", "state.json"); }

// ── Outcome reporting ──────────────────────────────────────────────────────
// After finishing, an RP may report whether the approval actually worked
// (e.g. a PDS that rejects the DID document after the redirect) using its
// access token; the wallet reads it back by capability id. Persisted (unlike
// tokens) so a report outlives a restart; bounded by age and entry count.
type OAuthOutcome = { status: "active" | "failed"; reason?: string; updatedAt: string };
const OUTCOME_MAX_AGE_MS = 30 * 24 * 3600_000;
const OUTCOME_MAX_ENTRIES = 10_000;
const OUTCOME_MAX_REASON = 200;
let oauthOutcomes: Map<string, OAuthOutcome> | undefined;
function outcomesPath() { return join(DATA_DIR, "oauth", "outcomes.json"); }
function loadOutcomes(): Map<string, OAuthOutcome> {
  if (oauthOutcomes) return oauthOutcomes;
  const map = new Map<string, OAuthOutcome>();
  try {
    const source = read(outcomesPath());
    const value = source === null ? undefined : JSON.parse(source);
    if (isObj(value)) for (const [id, item] of Object.entries(value)) {
      if (!isObj(item) || (item.status !== "active" && item.status !== "failed") || typeof item.updatedAt !== "string") continue;
      map.set(id, { status: item.status, ...(typeof item.reason === "string" ? { reason: item.reason } : {}), updatedAt: item.updatedAt });
    }
  } catch { /* an unreadable outcomes file is treated as empty; outcomes are advisory */ }
  return oauthOutcomes = map;
}
function saveOutcomes(now = Date.now()) {
  const map = loadOutcomes();
  for (const [id, item] of map) if (!(now - Date.parse(item.updatedAt) < OUTCOME_MAX_AGE_MS)) map.delete(id);
  if (map.size > OUTCOME_MAX_ENTRIES) {
    const oldest = [...map].sort((a, b) => Date.parse(a[1].updatedAt) - Date.parse(b[1].updatedAt)).slice(0, map.size - OUTCOME_MAX_ENTRIES);
    for (const [id] of oldest) map.delete(id);
  }
  atomicWrite(outcomesPath(), JSON.stringify(Object.fromEntries(map)));
}

function oauthRegistrationAddress(request: Request) {
  // api.did.md is bound only to loopback and is reached through Caddy behind
  // Cloudflare. CF-Connecting-IP is therefore the only forwarded address we
  // accept as a per-client bucket; direct/local requests deliberately share
  // a small fallback bucket rather than trusting a forgeable X-Forwarded-For.
  const value = request.headers.get("cf-connecting-ip") ?? "unknown";
  return /^[0-9a-f:.]{3,64}$/i.test(value) ? value.toLowerCase() : "unknown";
}
function consumeOauthRegistration(request: Request) {
  const now = Date.now();
  for (const [key, value] of oauthRegistrationRates) if (value.resetAt <= now) oauthRegistrationRates.delete(key);
  const key = oauthRegistrationAddress(request); const current = oauthRegistrationRates.get(key);
  if (current && current.resetAt > now) {
    if (current.count >= OAUTH_MAX_REGISTRATIONS_PER_WINDOW) throw new Invalid("client registration rate limit exceeded; try again later");
    current.count += 1; return;
  }
  oauthRegistrationRates.set(key, { count: 1, resetAt: now + OAUTH_REGISTRATION_WINDOW_MS });
}
function oauthState(): OAuthState {
  const source = read(oauthPath());
  if (source === null) return { clients: {} };
  try {
    const value = JSON.parse(source);
    if (!isObj(value) || !isObj(value.clients)) throw new Error();
    return { clients: value.clients as unknown as Record<string, OAuthClient> };
  } catch { throw new Invalid("OAuth authorization state is invalid"); }
}
function saveOauthState(value: OAuthState) { atomicWrite(oauthPath(), JSON.stringify(value)); }
function cleanupOauthTokens(now = Date.now()) {
  for (const [key, code] of oauthCodes) if (Date.parse(code.expiresAt) <= now) oauthCodes.delete(key);
  for (const [key, token] of oauthTokens) if (Date.parse(token.expiresAt) <= now) oauthTokens.delete(key);
  for (const [key, callback] of oauthFileCallbacks) if (Date.parse(callback.expiresAt) <= now) oauthFileCallbacks.delete(key);
}

// PLAN6: a relying party may authenticate as a did:webvh DID (JAR,
// client_id_scheme=did) instead of a DCR-issued client_XXXX id. Both shapes
// flow through every call site below unchanged; DID-scheme clients are
// never looked up in state.clients (no DCR registration exists for them --
// see oauthAuthorizeComplete's own branch, which resolves the DID document
// directly instead).
function oauthClientId(value: Json | undefined, label = "client_id") {
  if (typeof value !== "string" || value.length > 256 || !(/^client_[A-Za-z0-9_-]{32,128}$/.test(value) || /^did:webvh:[A-Za-z0-9]{1,64}:[A-Za-z0-9.%-]{1,253}(?::[A-Za-z0-9._~%-]{1,128}){0,8}$/.test(value))) throw new Invalid(`${label} is invalid`);
  return value;
}
function oauthCode(value: Json | undefined) {
  if (typeof value !== "string" || !/^code_[A-Za-z0-9_-]{32,128}$/.test(value)) throw new Invalid("authorization code is invalid");
  return value;
}
function oauthScope(value: Json | undefined, label: string) {
  if (typeof value !== "string" || value.length < 1 || value.length > 1024 || value.trim() !== value) throw new Invalid(`${label} is invalid`);
  const scopes = value.split(" ");
  if (!scopes.length || scopes.length > OAUTH_MAX_SCOPES || new Set(scopes).size !== scopes.length || scopes.some(scope => !/^[A-Za-z][A-Za-z0-9:._/-]{0,95}$/.test(scope))) throw new Invalid(`${label} is invalid`);
  return scopes;
}
function oauthExactScope(value: Json | undefined, permitted: string[], label: string) {
  if (!Array.isArray(value) || value.length < 1 || value.length > OAUTH_MAX_SCOPES || value.some(item => typeof item !== "string")) throw new Invalid(`${label} is invalid`);
  const scopes = value as string[];
  if (new Set(scopes).size !== scopes.length || scopes.some(scope => !permitted.includes(scope))) throw new Invalid(`${label} is not registered for this client`);
  return scopes;
}
function oauthRedirect(value: Json | undefined, label = "redirect_uri") {
  if (typeof value !== "string" || value.length > 1024) throw new Invalid(`${label} is invalid`);
  try {
    const parsed = new URL(value);
    if ((parsed.protocol !== "https:" && !isLoopbackDevelopmentOrigin(parsed) && !isLocalFileRedirect(parsed)) || parsed.username || parsed.password || parsed.hash || parsed.toString() !== value) throw new Error();
    return value;
  } catch { throw new Invalid(`${label} must be an exact HTTPS URI without a fragment, an HTTP loopback development URI, or a local file URI`); }
}
function oauthClientOrigin(client: OAuthClient) {
  const origins = [...new Set(client.redirectUris.map(uri => new URL(uri).origin))];
  return origins.length === 1 ? origins[0] : undefined;
}
function oauthClientBody(client: OAuthClient) {
  const endpoint = `${OAUTH_ISSUER}/v1/oauth/register/${encodeURIComponent(client.clientId)}`;
  return {
    client_id: client.clientId, client_name: client.clientName, application_type: "web",
    redirect_uris: client.redirectUris, grant_types: ["authorization_code"], response_types: ["code"],
    token_endpoint_auth_method: "none", scope: client.scopes.join(" "),
    outcome_reporting: client.outcomeReporting === true,
    registration_client_uri: endpoint,
  };
}
function oauthRegistrationToken(request: Request, client: OAuthClient) {
  const match = /^Bearer ([A-Za-z0-9_-]{32,256})$/.exec(request.headers.get("authorization") ?? "");
  if (!match) throw new Invalid("a registration access token is required");
  return sha256B64url(match[1]!).then(hash => {
    if (hash !== client.registrationTokenHash) throw new Invalid("registration access token is invalid");
  });
}
// PLAN3: the OID4VP DCQL response format is `{ "<credential_query_id>":
// [<credential>, ...] }`. v1 always requests exactly one capability
// credential under a fixed query id -- did.md generates this DCQL query
// itself (from the /authorize request's capability_type, see
// oauthAuthorizeParameters-side handling), so there is nothing for an RP to
// author here (PLAN3 §0.4's deliberate v1 scope limit).
const CAPABILITY_DCQL_QUERY_ID = "capability";
const VC_CONTEXT = "https://www.w3.org/ns/credentials/v2";
function oauthVcFromVpToken(value: Json | undefined): Obj {
  const input = asObj(value, "vp_token"); strictObjectKeys(input, [CAPABILITY_DCQL_QUERY_ID], "vp_token");
  const credentials = input[CAPABILITY_DCQL_QUERY_ID];
  if (!Array.isArray(credentials) || credentials.length !== 1) throw new Invalid("vp_token must contain exactly one capability credential");
  return asObj(credentials[0], "capability credential");
}
/**
 * OAuth authorization_details is deliberately opaque to the authorization
 * server.  A relying party may define its own detail types; the Wallet signs
 * the resulting list, while this server only keeps it bounded and binds the
 * enclosing capability to its registered audience and DPoP key.
 */
function oauthAuthorizationDetails(value: Json | undefined) {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > 16) throw new Invalid("device capability authorizationDetails is invalid");
  if (new TextEncoder().encode(JSON.stringify(value)).length > 16_384) throw new Invalid("device capability authorizationDetails is too large");
  for (const [index, detail] of value.entries()) {
    const object = asObj(detail, `device capability authorizationDetails[${index}]`);
    if (typeof object.type !== "string" || !/^[A-Za-z][A-Za-z0-9:._/-]{0,127}$/.test(object.type)) throw new Invalid(`device capability authorizationDetails[${index}].type is invalid`);
  }
  return value;
}
// PLAN2: the capability document's
// type name is owned by the relying party, not by did.md -- "did.md/
// DeviceCapability" is no longer a required, hardcoded value. This server
// only checks the type is a well-formed namespaced string (same shape as an
// authorizationDetails[].type, see oauthAuthorizationDetails above); the RP
// decides what its own type name means and validates its own document
// fields. See verifiedOauthCapability for the (still opaque to this server)
// scope/authorizationDetails contents.
function capabilityType(value: Json | undefined) {
  if (typeof value !== "string" || !/^[A-Za-z][A-Za-z0-9:._/-]{0,127}$/.test(value)) throw new Invalid("device capability type is invalid");
  return value;
}
// PLAN3: `value` is a bare VC (either freshly unwrapped from a vp_token by
// the caller, or re-passed from storage -- see oauthAuthorizeComplete and
// oauthToken, which both pass the same bare-VC shape here, exactly as the
// pre-PLAN3 {document,proof} pair was). VC-DM 2.0 envelope fields
// (@context/id/type/issuer/credentialSubject/proof) are checked here; the
// RP-owned content that used to be flat now lives in credentialSubject --
// see PLAN2-capability-ownership.md for why that content stays opaque to
// this server (only shape-checked generically, never interpreted).
async function verifiedOauthCapability(value: Json | undefined, state: OAuthState, suppliedAuthority?: AuthenticationAuthority) {
  const vc = asObj(value, "capability credential");
  strictObjectKeys(vc, ["@context", "id", "type", "issuer", "credentialSubject", "proof"], "capability credential");
  if (!Array.isArray(vc["@context"]) || vc["@context"].length !== 1 || vc["@context"][0] !== VC_CONTEXT) throw new Invalid("capability credential @context is invalid");
  if (!Array.isArray(vc.type) || vc.type.length !== 2 || vc.type[0] !== "VerifiableCredential") throw new Invalid("capability credential type is invalid");
  capabilityType(vc.type[1] as Json | undefined);
  const id = opaqueId(vc.id, "capability credential id");
  const issuer = typeof vc.issuer === "string" ? vc.issuer : (() => { throw new Invalid("capability credential issuer is invalid"); })();
  const subject = asObj(vc.credentialSubject, "capability credential subject");
  const ordinaryCapabilityKeys = ["audience", "expiresAt", "issuedAt", "scope"];
  // deviceJkt is optional: only DPoP-bound clients (device-capability
  // consumers like biset) supply one. A conventional relying party has no
  // DPoP key at all -- its capability credential simply omits the field,
  // rather than the shape diverging by client kind.
  strictObjectKeys(subject, [...ordinaryCapabilityKeys, ...(own(subject, "deviceJkt") ? ["deviceJkt"] : []), ...(own(subject, "authorizationDetails") ? ["authorizationDetails"] : [])], "capability credential subject");
  // PLAN6: a did:webvh-authenticated client has no DCR registration at all
  // (§0.3) -- its legitimacy was already established by DID resolution
  // (oauthAuthorizeComplete's own redirect_uri check, gated by
  // OAUTH_DID_RP_DOMAINS), not by a state.clients lookup, so that lookup
  // (and the registered-scope allowlist it would otherwise supply) does
  // not apply here. Its requested scope is instead just shape-validated
  // (oauthScope, the same check a DCR client's own /authorize request
  // parameter gets) -- there is no separate registration-time promise to
  // cross-check it against.
  const clientId = oauthClientId(subject.audience, "capability credential audience");
  const isDidClient = clientId.startsWith("did:webvh:");
  const client = isDidClient ? undefined : state.clients[clientId];
  if (!isDidClient && !client) throw new Invalid("device capability client is not registered");
  const deviceJkt = own(subject, "deviceJkt")
    ? (typeof subject.deviceJkt === "string" && /^[A-Za-z0-9_-]{43}$/.test(subject.deviceJkt) ? subject.deviceJkt : (() => { throw new Invalid("device capability DPoP thumbprint is invalid"); })())
    : undefined;
  const issuedAt = validTime(subject.issuedAt, "capability credential issuedAt"); const expiresAt = validTime(subject.expiresAt, "capability credential expiresAt");
  const issued = Date.parse(issuedAt); const expires = Date.parse(expiresAt);
  if (expires <= issued || expires - issued > OAUTH_CAPABILITY_MAX_MS || issued > Date.now() + AUTH_PROOF_CLOCK_SKEW_MS || expires <= Date.now()) throw new Invalid("device capability lifetime is invalid");
  if (!Array.isArray(subject.scope) || subject.scope.length < 1 || subject.scope.length > OAUTH_MAX_SCOPES || new Set(subject.scope).size !== subject.scope.length || subject.scope.some(item => typeof item !== "string" || !/^[A-Za-z][A-Za-z0-9:._/-]{0,95}$/.test(item))) throw new Invalid("capability credential scope is invalid");
  const grantedScope = client ? oauthExactScope(subject.scope, client.scopes, "capability credential scope") : subject.scope as string[];
  oauthAuthorizationDetails(subject.authorizationDetails);
  // Data Integrity Proof convention: the proof is computed over the
  // credential WITHOUT its own `proof` property (see
  // client/did-webvh.ts's createDataIntegrityProof) -- strip it back off
  // before hashing, the same shape the Wallet actually signed.
  const { proof: vcProof, ...unsignedVc } = vc;
  await verifyAuthenticationProof(unsignedVc, vcProof, issuer, OAUTH_CAPABILITY_MAX_MS, suppliedAuthority);
  return { id, issuer, clientId, deviceJkt, scope: grantedScope, expiresAt, signed: vc };
}
// One discovery document serves both /.well-known/oauth-authorization-server
// and /.well-known/openid-configuration: there is only one protocol now, and
// an id_token (when "openid" is requested) is signed by the Wallet's own
// DID key, not any key this server holds -- so there is deliberately no
// jwks_uri. A relying party verifies an id_token by resolving its `kid`
// (an absolute `<did>#<fragment>` -- the fragment is whatever the DID's own
// authentication array names, not assumed to be "#pass-1") against that
// DID's own published did.jsonl, the same way this server's own
// verifySelfIssuedIdToken does.
//
// id_token_signing_alg_values_supported below MUST stay in sync with
// jwtAlgForKeyType's cases: it advertises every alg this server's own
// verifySelfIssuedIdToken can actually verify, not an aspirational list.
function oauthMetadata(request: Request) {
  return oauthJson(request, {
    issuer: OAUTH_ISSUER,
    authorization_endpoint: "https://app.did.md/authorize",
    token_endpoint: `${OAUTH_ISSUER}/v1/oauth/token`,
    userinfo_endpoint: `${OAUTH_ISSUER}/v1/oauth/userinfo`,
    registration_endpoint: `${OAUTH_ISSUER}/v1/oauth/register`,
    scopes_supported: ["openid", "profile", "email"],
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    subject_types_supported: ["public"],
    subject_syntax_types_supported: ["did:webvh"],
    id_token_signing_alg_values_supported: ["EdDSA"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    dpop_signing_alg_values_supported: ["ES256"],
    claims_supported: ["sub", "did", "preferred_username", "nickname", "name", "email", "email_verified"],
  });
}
function oauthOutcomeFlag(value: Json | undefined) {
  if (value !== undefined && typeof value !== "boolean") throw new Invalid("outcome_reporting must be a boolean");
  return value === true;
}
async function oauthRegister(request: Request) {
  const body = asObj(JSON.parse(await requestBody(request, 1 << 16)), "client registration request");
  onlyKeys(body, ["application_type", "client_name", "grant_types", "redirect_uris", "outcome_reporting", "response_types", "scope", "token_endpoint_auth_method"], "client registration request");
  if (body.application_type !== "web" || body.token_endpoint_auth_method !== "none") throw new Invalid("only public web clients are supported");
  if (typeof body.client_name !== "string" || !body.client_name.trim() || body.client_name.length > 120) throw new Invalid("client_name is invalid");
  if (!Array.isArray(body.redirect_uris) || body.redirect_uris.length < 1 || body.redirect_uris.length > OAUTH_MAX_REDIRECTS || body.redirect_uris.some(value => typeof value !== "string")) throw new Invalid("redirect_uris is invalid");
  const redirectUris = (body.redirect_uris as string[]).map(uri => oauthRedirect(uri)); if (new Set(redirectUris).size !== redirectUris.length) throw new Invalid("redirect_uris contains a duplicate");
  if (!Array.isArray(body.grant_types) || body.grant_types.length !== 1 || body.grant_types[0] !== "authorization_code") throw new Invalid("grant_types is invalid");
  if (!Array.isArray(body.response_types) || body.response_types.length !== 1 || body.response_types[0] !== "code") throw new Invalid("response_types is invalid");
  const scopes = oauthScope(body.scope, "scope");
  const outcomeReporting = oauthOutcomeFlag(body.outcome_reporting);
  return exclusive("oauth", async () => {
    const state = oauthState();
    consumeOauthRegistration(request);
    if (Object.keys(state.clients).length >= OAUTH_MAX_CLIENTS) throw new Invalid("client registration capacity is reached");
    const clientId = `client_${randomB64url(32)}`; const registrationAccessToken = randomB64url(32); const now = isoAt(Date.now());
    const client: OAuthClient = { clientId, clientName: body.client_name.trim(), redirectUris, scopes, createdAt: now, updatedAt: now, registrationTokenHash: await sha256B64url(registrationAccessToken), ...(outcomeReporting ? { outcomeReporting } : {}) };
    state.clients[clientId] = client; saveOauthState(state);
    console.info(JSON.stringify({ event: "oauth.client_registered", clientId, origin: oauthClientOrigin(client) ?? null, time: now }));
    return oauthJson(request, { ...oauthClientBody(client), registration_access_token: registrationAccessToken }, 201);
  });
}
async function oauthClientConfiguration(request: Request, clientId: string) {
  return exclusive("oauth", async () => {
    const state = oauthState(); const client = state.clients[clientId]; if (!client) throw new Invalid("client registration was not found");
    await oauthRegistrationToken(request, client);
    if (request.method === "GET") return oauthJson(request, oauthClientBody(client));
    if (request.method === "DELETE") { delete state.clients[clientId]; saveOauthState(state); console.info(JSON.stringify({ event: "oauth.client_deleted", clientId, time: isoAt(Date.now()) })); return new Response(null, { status: 204, headers: oauthCors(request) }); }
    if (request.method !== "PUT") return new Response(null, { status: 405, headers: oauthCors(request) });
    const body = asObj(JSON.parse(await requestBody(request, 1 << 16)), "client configuration request");
    onlyKeys(body, ["application_type", "client_id", "client_name", "grant_types", "outcome_reporting", "redirect_uris", "response_types", "scope", "token_endpoint_auth_method"], "client configuration request");
    if (body.client_id !== clientId || body.application_type !== "web" || body.token_endpoint_auth_method !== "none" || typeof body.client_name !== "string" || !body.client_name.trim() || body.client_name.length > 120) throw new Invalid("client configuration is invalid");
    if (!Array.isArray(body.redirect_uris) || body.redirect_uris.length < 1 || body.redirect_uris.length > OAUTH_MAX_REDIRECTS || body.redirect_uris.some(value => typeof value !== "string")) throw new Invalid("redirect_uris is invalid");
    if (!Array.isArray(body.grant_types) || body.grant_types.length !== 1 || body.grant_types[0] !== "authorization_code" || !Array.isArray(body.response_types) || body.response_types.length !== 1 || body.response_types[0] !== "code") throw new Invalid("client configuration is invalid");
    const redirectUris = (body.redirect_uris as string[]).map(uri => oauthRedirect(uri)); if (new Set(redirectUris).size !== redirectUris.length) throw new Invalid("redirect_uris contains a duplicate");
    const scopes = oauthScope(body.scope, "scope"); const updated: OAuthClient = { ...client, clientName: body.client_name.trim(), redirectUris, scopes, outcomeReporting: oauthOutcomeFlag(body.outcome_reporting), updatedAt: isoAt(Date.now()) };
    state.clients[clientId] = updated; saveOauthState(state); return oauthJson(request, oauthClientBody(updated));
  });
}
async function oauthPublicClient(request: Request, clientId: string) {
  return exclusive("oauth", async () => {
    const state = oauthState(); const client = state.clients[clientId]; if (!client) throw new Invalid("client registration was not found");
    return oauthJson(request, { client_id: client.clientId, client_name: client.clientName, redirect_uris: client.redirectUris, scope: client.scopes.join(" "), outcome_reporting: client.outcomeReporting === true, ...(oauthClientOrigin(client) ? { client_origin: oauthClientOrigin(client)! } : {}) });
  });
}
// A DID that has never been published anywhere can still authorize: the
// Wallet supplies its own never-submitted genesis entry, and this derives
// the same authentication key from it directly instead of resolving a
// hosted did.jsonl -- "authenticate before you've published anywhere" (see
// verifyAuthenticationProof's suppliedAuthority). Shared by
// oauthAuthorizeComplete and oauthToken's own re-verification, so a code
// issued this way can still be redeemed for a token afterward.
async function suppliedAuthorityFromDidLog(didLog: string, expectedDid: string) {
  if (new TextEncoder().encode(didLog).length > 32_768) throw new Invalid("provisional DID log is invalid");
  const entries = parseJsonl(didLog);
  if (entries.length !== 1) throw new Invalid("the supplied DID log must contain only its genesis entry");
  const checked = await validateLog(entries, [], "", false);
  // The genesis entry's OWN state.id is whatever placeholder/original
  // domain it was created under -- not necessarily this identity's current
  // one (a host move/connect changes the domain segment but keeps the
  // SCID). #pass-1 is recorded as a relative reference specifically so it
  // resolves the same regardless, so the authority is built against
  // expectedDid (the capability's own issuer), only cross-checked here by
  // SCID, not by the genesis's own literal DID string.
  if (parseDid(checked.latest.state.id as string).scid !== parseDid(expectedDid).scid || checked.parameters.deactivated || checked.parameters.portable !== true) throw new Invalid("DID genesis does not authorize this SCID");
  return authenticationKeyFromState(expectedDid, checked.latest.state);
}
async function oauthAuthorizeComplete(request: Request) {
  const body = asObj(JSON.parse(await requestBody(request, 1 << 16)), "authorization completion request");
  strictObjectKeys(body, ["vp_token", "client_id", "code_challenge", "code_challenge_method", "redirect_uri", "state", ...(own(body, "id_token") ? ["id_token"] : []), ...(own(body, "did_log") ? ["did_log"] : [])], "authorization completion request");
  const clientId = oauthClientId(body.client_id); const redirectUri = oauthRedirect(body.redirect_uri); if (body.code_challenge_method !== "S256" || typeof body.code_challenge !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(body.code_challenge)) throw new Invalid("PKCE code challenge is invalid");
  if (typeof body.state !== "string" || !/^[A-Za-z0-9._~-]{16,512}$/.test(body.state)) throw new Invalid("state is invalid");
  if (own(body, "did_log") && typeof body.did_log !== "string") throw new Invalid("provisional DID log is invalid");
  // Peeked, not yet trusted -- only used to pick which DID the did_log (if
  // any) is meant to authorize; verifiedOauthCapability below still fully
  // validates the capability credential (and this issuer) on its own.
  const peekedCredentials = isObj(body.vp_token) && Array.isArray(body.vp_token[CAPABILITY_DCQL_QUERY_ID]) ? body.vp_token[CAPABILITY_DCQL_QUERY_ID] as Json[] : undefined;
  const peekedVc = peekedCredentials && peekedCredentials.length === 1 && isObj(peekedCredentials[0]) ? peekedCredentials[0] as Obj : undefined;
  const peekedIssuer = peekedVc && typeof peekedVc.issuer === "string" ? peekedVc.issuer as string : undefined;
  const suppliedAuthority = typeof body.did_log === "string" && peekedIssuer ? await suppliedAuthorityFromDidLog(body.did_log, peekedIssuer) : undefined;
  // PLAN6 §0.3bis: a DID-scheme client has no DCR registration at all -- its
  // redirect_uri is authenticated by being published in its own DID
  // document's `service` array, which only the RP's own DID private key
  // could have signed into existence in the first place (dito frontend
  // already checked this once, client-side, before showing the consent
  // screen -- see client/app.ts's jarAuthorizationParameters; this endpoint
  // is a public HTTP API independent of that browser flow and must not
  // trust it, so the same check is repeated here).
  // Fail closed *before* any resolution is attempted: an unauthenticated
  // caller must not be able to make this server fetch an arbitrary domain
  // of their choosing (SSRF -- see OAUTH_DID_RP_DOMAINS's own comment).
  if (clientId.startsWith("did:webvh:") && !oauthDidClientDomainAllowed(clientId)) throw new Invalid("client_id's domain is not an accepted relying party domain");
  const didRedirectCheck = clientId.startsWith("did:webvh:")
    ? resolveDidWebvhDocument(clientId).then(document => {
        const service = Array.isArray(document.service) ? document.service : [];
        if (!service.some(entry => isObj(entry) && entry.serviceEndpoint === redirectUri)) throw new Invalid("authorization redirect URI is not published by the relying party's own DID document");
      })
    : undefined;
  return exclusive("oauth", async () => {
    const state = oauthState();
    if (didRedirectCheck) { await didRedirectCheck; }
    else { const client = state.clients[clientId]; if (!client || !client.redirectUris.includes(redirectUri)) throw new Invalid("authorization redirect URI is not registered"); }
    const vc = oauthVcFromVpToken(body.vp_token);
    const capability = await verifiedOauthCapability(vc, state, suppliedAuthority);
    if (capability.clientId !== clientId) throw new Invalid("device capability is not authorized");
    // The id_token is the Wallet's own self-issued token (see
    // createSelfIssuedIdToken), present only when the client requested
    // "openid" -- verified here for defense in depth, then passed through
    // verbatim at the token endpoint. This server never signs one itself.
    if (own(body, "id_token")) {
      if (typeof body.id_token !== "string" || body.id_token.length > 8192) throw new Invalid("id_token is invalid");
      if (!capability.scope.includes("openid")) throw new Invalid("id_token was supplied without the openid scope");
      await verifySelfIssuedIdToken(body.id_token, capability.issuer, clientId, OAUTH_CAPABILITY_MAX_MS, suppliedAuthority);
    } else if (capability.scope.includes("openid")) throw new Invalid("id_token is required for the openid scope");
    cleanupOauthTokens();
    const code = `code_${randomB64url(32)}`; const codeHash = await sha256B64url(code);
    const expiresAt = isoAt(Date.now() + OAUTH_CODE_MS);
    oauthCodes.set(codeHash, { clientId, redirectUri, did: capability.issuer, capability: capability.signed, capabilityId: capability.id, deviceJkt: capability.deviceJkt, scope: capability.scope, codeChallenge: body.code_challenge, expiresAt, ...(typeof body.id_token === "string" ? { idToken: body.id_token } : {}), ...(typeof body.did_log === "string" ? { didLog: body.did_log } : {}) });
    if (isLocalFileRedirect(new URL(redirectUri))) oauthFileCallbacks.set(body.state, { clientId, code, expiresAt });
    return oauthJson(request, { code, state: body.state, redirect_uri: redirectUri, iss: OAUTH_ISSUER });
  });
}
async function oauthFileCallback(request: Request, url: URL) {
  const clientId = oauthClientId(url.searchParams.get("client_id"));
  const state = url.searchParams.get("state");
  if (typeof state !== "string" || !/^[A-Za-z0-9._~-]{16,512}$/.test(state)) throw new Invalid("state is invalid");
  return exclusive("oauth", async () => {
    const client = oauthState().clients[clientId];
    if (!client || !client.redirectUris.some(uri => isLocalFileRedirect(new URL(uri)))) throw new Invalid("local file client registration was not found");
    cleanupOauthTokens();
    const callback = oauthFileCallbacks.get(state);
    if (!callback || callback.clientId !== clientId) return new Response(null, { status: 204, headers: { ...oauthCors(request), "cache-control": "no-store" } });
    return oauthJson(request, { code: callback.code, state, iss: OAUTH_ISSUER });
  });
}
async function oauthIssueToken(request: Request, capability: { id: string; issuer: string; clientId: string; deviceJkt?: string; scope: string[]; expiresAt: string; signed: OAuthCapability }, dpop: { jkt: string } | undefined, idToken?: string) {
  // A capability with no deviceJkt (a conventional, non-DPoP relying party --
  // see verifiedOauthCapability) issues a plain Bearer token instead: there
  // is no device key to bind it to, and none was presented, so none is
  // required or accepted.
  if (capability.deviceJkt) { if (!dpop || dpop.jkt !== capability.deviceJkt) throw new Invalid("DPoP key is not the authorized device key"); }
  else if (dpop) throw new Invalid("this authorization does not use DPoP");
  cleanupOauthTokens();
  const token = randomB64url(); const tokenHash = await sha256B64url(token);
  const nonce = capability.deviceJkt ? randomB64url(24) : undefined;
  const expiresAt = isoAt(Date.now() + OAUTH_TOKEN_MS);
  oauthTokens.set(tokenHash, { capabilityId: capability.id, did: capability.issuer, audience: capability.clientId, clientId: capability.clientId, deviceJkt: capability.deviceJkt, scope: capability.scope, expiresAt, nonce });
  return oauthJson(request, {
    access_token: token, token_type: capability.deviceJkt ? "DPoP" : "Bearer",
    expires_in: Math.floor(OAUTH_TOKEN_MS / 1000), scope: capability.scope.join(" "),
    sub: capability.issuer, vp_token: capability.signed,
    ...(idToken ? { id_token: idToken } : {}),
  }, 200, nonce ? { "dpop-nonce": nonce } : {});
}
// RFC 6749 §4.1.3 requires the token endpoint to accept
// application/x-www-form-urlencoded -- dito/biset both send JSON instead
// (their own choice, fine for a client this server also controls), but a
// standard-conforming OAuth client (oidc-bridge's DitoClient, and any
// future generic OIDC client) sends form-encoded per spec. This server
// used to require form-encoding here (see the pre-2026-09 history of this
// function) and was changed to JSON-only at some point without adding a
// form-encoded path back -- the result silently broke oidc-bridge (found
// live 2026-09-21 as an uncaught JSON.parse SyntaxError, surfaced to the
// RP as a bare 500). Both are accepted now, keyed off Content-Type.
async function oauthTokenRequestBody(request: Request): Promise<Obj> {
  const raw = await requestBody(request, 1 << 16);
  const contentType = (request.headers.get("content-type") ?? "").toLowerCase();
  if (contentType.startsWith("application/x-www-form-urlencoded")) {
    const params = new URLSearchParams(raw);
    const value: Obj = {};
    for (const [key, entry] of params) { if (own(value, key)) throw new Invalid(`token request contains a duplicate ${key}`); value[key] = entry; }
    return value;
  }
  return asObj(JSON.parse(raw), "token request");
}
async function oauthToken(request: Request) {
  const body = await oauthTokenRequestBody(request); strictObjectKeys(body, ["client_id", "code", "code_verifier", "grant_type", "redirect_uri"], "token request");
  if (body.grant_type !== "authorization_code") throw new Invalid("grant_type is unsupported"); const clientId = oauthClientId(body.client_id); const redirectUri = oauthRedirect(body.redirect_uri); const code = oauthCode(body.code);
  if (typeof body.code_verifier !== "string" || !/^[A-Za-z0-9_-]{43,128}$/.test(body.code_verifier)) throw new Invalid("PKCE verifier is invalid");
  const dpopHeader = request.headers.get("dpop");
  const dpop = dpopHeader ? await verifyP256Dpop(dpopHeader, request, `${OAUTH_ISSUER}/v1/oauth/token`) : undefined;
  return exclusive("oauth", async () => {
    const state = oauthState(); cleanupOauthTokens(); const codeHash = await sha256B64url(code); const stored = oauthCodes.get(codeHash);
    if (!stored || stored.clientId !== clientId || stored.redirectUri !== redirectUri || await sha256B64url(body.code_verifier) !== stored.codeChallenge) throw new Invalid("authorization code is invalid");
    oauthCodes.delete(codeHash);
    const suppliedAuthority = stored.didLog !== undefined ? await suppliedAuthorityFromDidLog(stored.didLog, stored.did) : undefined;
    const capability = await verifiedOauthCapability(stored.capability as unknown as Json, state, suppliedAuthority);
    if (capability.id !== stored.capabilityId || capability.issuer !== stored.did || capability.deviceJkt !== stored.deviceJkt) throw new Invalid("authorization code capability is invalid");
    return oauthIssueToken(request, capability, dpop, stored.idToken);
  });
}
async function oauthRefresh(request: Request) {
  const body = asObj(JSON.parse(await requestBody(request, 1 << 16)), "device refresh request"); strictObjectKeys(body, ["vp_token", "client_id"], "device refresh request"); const clientId = oauthClientId(body.client_id);
  const dpop = await verifyP256Dpop(request.headers.get("dpop") ?? "", request, `${OAUTH_ISSUER}/v1/oauth/device-refresh`);
  return exclusive("oauth", async () => {
    const state = oauthState(); const vc = oauthVcFromVpToken(body.vp_token); const capability = await verifiedOauthCapability(vc, state);
    if (capability.clientId !== clientId) throw new Invalid("device capability client does not match the request");
    return oauthIssueToken(request, capability, dpop);
  });
}
async function oauthResource(request: Request) {
  const auth = request.headers.get("authorization") ?? ""; const match = /^DPoP ([A-Za-z0-9_-]{20,512})$/.exec(auth); if (!match) throw new Invalid("a DPoP access token is required");
  return exclusive("oauth", async () => {
    cleanupOauthTokens(); const tokenHash = await sha256B64url(match[1]!); const token = oauthTokens.get(tokenHash); if (!token) throw new Invalid("access token is invalid or expired");
    const dpop = await verifyP256Dpop(request.headers.get("dpop") ?? "", request, `${OAUTH_ISSUER}/v1/oauth/resource`, token.nonce); if (dpop.jkt !== token.deviceJkt) throw new Invalid("DPoP key does not match this access token");
    token.nonce = randomB64url(24); oauthTokens.set(tokenHash, token);
    return oauthJson(request, { ok: true, sub: token.did, client_id: token.clientId, scope: token.scope, message: "DPoP-bound OAuth device session accepted." }, 200, { "dpop-nonce": token.nonce });
  });
}

// For a Bearer (non-DPoP) access token -- the id_token itself already
// carries the same profile claims (self-issued, see approveAuthorization in
// client/app.ts), so this is a compatibility convenience for a relying
// party that always calls userinfo out of habit, not a second source of
// truth.
async function oauthUserinfo(request: Request) {
  const match = /^Bearer ([A-Za-z0-9_-]{20,512})$/.exec(request.headers.get("authorization") ?? ""); if (!match) throw new Invalid("a Bearer access token is required");
  return exclusive("oauth", async () => {
    cleanupOauthTokens(); const token = oauthTokens.get(await sha256B64url(match[1]!));
    if (!token || token.deviceJkt) throw new Invalid("access token is invalid or expired");
    const username = parseDid(token.did).scid;
    return oauthJson(request, {
      sub: token.did,
      ...(token.scope.includes("profile") ? { did: token.did, preferred_username: username, nickname: username, name: username } : {}),
      ...(token.scope.includes("email") ? { email: `${username}@users.did.invalid`, email_verified: false } : {}),
    });
  });
}

// The RP reports whether the approval worked, authenticated by the Bearer
// access token it received (the token's capabilityId names the approval).
// DPoP-bound tokens are rejected (401): DPoP clients are the wallet's own
// devices, and per-request proof/nonce handling is not worth it for a
// server-to-server report. "active" is final; "failed" may be superseded.
async function oauthOutcomeReport(request: Request) {
  const unauthorized = () => oauthJson(request, { error: "invalid_token" }, 401, { "www-authenticate": "Bearer" });
  const match = /^Bearer ([A-Za-z0-9_-]{20,512})$/.exec(request.headers.get("authorization") ?? ""); if (!match) return unauthorized();
  const tokenHash = await sha256B64url(match[1]!);
  return exclusive("oauth", async () => {
    cleanupOauthTokens(); const token = oauthTokens.get(tokenHash);
    if (!token || token.deviceJkt) return unauthorized();
    let body: Obj;
    try { body = asObj(JSON.parse(await requestBody(request, 1 << 12)), "outcome report"); } catch (error) { if (error instanceof Invalid) throw error; throw new Invalid("outcome report is invalid"); }
    onlyKeys(body, ["status", "reason"], "outcome report");
    if (body.status !== "active" && body.status !== "failed") throw new Invalid("status must be \"active\" or \"failed\"");
    if (body.reason !== undefined && typeof body.reason !== "string") throw new Invalid("reason must be a string");
    const reason = typeof body.reason === "string" ? body.reason.trim() : "";
    if (reason.length > OUTCOME_MAX_REASON) throw new Invalid(`reason must be at most ${OUTCOME_MAX_REASON} characters`);
    const outcomes = loadOutcomes(); const current = outcomes.get(token.capabilityId);
    if (current?.status === "active") return new Response(null, { status: 204, headers: oauthCors(request) });
    outcomes.set(token.capabilityId, { status: body.status, ...(body.status === "failed" && reason ? { reason } : {}), updatedAt: isoAt(Date.now()) });
    saveOutcomes();
    return new Response(null, { status: 204, headers: oauthCors(request) });
  });
}
// Public: the capability id is an unguessable urn:uuid, read by the browser wallet.
function oauthOutcomeRead(request: Request, capabilityId: string) {
  const outcome = loadOutcomes().get(capabilityId);
  if (!outcome) return oauthJson(request, { status: "pending" }, 404);
  return oauthJson(request, outcome);
}

/** Every route this optional layer serves: discovery, DCR, and the
 * authorize/token/refresh/resource/userinfo endpoints. Returns undefined
 * for any path it does not own, so the caller (server.ts) can fall through
 * to identity-host.ts. */
export async function oauthFetch(request: Request, url: URL): Promise<Response | undefined> {
  if (url.pathname === "/.well-known/oauth-authorization-server" && request.method === "GET") return oauthMetadata(request);
  if (url.pathname === "/.well-known/openid-configuration" && request.method === "GET") return oauthMetadata(request);
  if (url.pathname === "/v1/oauth/register" && request.method === "POST") return await oauthRegister(request);
  const registration = /^\/v1\/oauth\/register\/(client_[A-Za-z0-9_-]{32,128})$/.exec(url.pathname);
  if (registration) return await oauthClientConfiguration(request, registration[1]!);
  const publicClient = /^\/v1\/oauth\/clients\/(client_[A-Za-z0-9_-]{32,128})$/.exec(url.pathname);
  if (publicClient && request.method === "GET") return await oauthPublicClient(request, publicClient[1]!);
  if (url.pathname === "/v1/oauth/authorize/complete" && request.method === "POST") return await oauthAuthorizeComplete(request);
  if (url.pathname === "/v1/oauth/file-callback" && request.method === "GET") return await oauthFileCallback(request, url);
  if (url.pathname === "/v1/oauth/token" && request.method === "POST") return await oauthToken(request);
  if (url.pathname === "/v1/oauth/device-refresh" && request.method === "POST") return await oauthRefresh(request);
  if (url.pathname === "/v1/oauth/resource" && request.method === "GET") return await oauthResource(request);
  if (url.pathname === "/v1/oauth/userinfo" && request.method === "GET") return await oauthUserinfo(request);
  if (url.pathname === "/v1/oauth/outcome" && request.method === "POST") return await oauthOutcomeReport(request);
  const outcome = /^\/v1\/oauth\/outcome\/([^/]{1,300})$/.exec(url.pathname);
  if (outcome && request.method === "GET") {
    let id: string; try { id = decodeURIComponent(outcome[1]!); } catch { throw new Invalid("capability id is invalid"); }
    return oauthOutcomeRead(request, id);
  }
  return undefined;
}
