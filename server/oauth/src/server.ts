import { readFileSync } from "node:fs";
import { pkceChallenge, DitoClient, randomBase64url } from "./dito-client.ts";
import { BridgeKeys } from "./keys.ts";
import { SessionStore, type BridgeSession } from "./session-store.ts";
// PLAN10: did.md's own optional
// OAuth/OID4VP convenience layer (DCR, code/token, biset's device-refresh),
// merged into this process rather than did-md-server's -- see server/ARD.md
// for why. oauthFetch is a self-contained route dispatcher (its own
// `/v1/oauth/*` + `/.well-known/oauth-authorization-server` paths, disjoint
// from every route this file already serves except
// `/.well-known/openid-configuration`, handled explicitly below) -- no
// state or route naming collides with this file's own Maps/paths.
import { oauthCors, oauthFetch } from "../oauth-server.ts";
import { Invalid } from "../../host/identity-host.ts";
import { serve } from "../../serve.ts";

type Client = { client_id: string; client_secret: string; redirect_uris: string[] };
type Code = { session: BridgeSession; expiresAt: number };
type AccessToken = { claims: Record<string, unknown>; expiresAt: number };

const issuer = (process.env.BRIDGE_ISSUER ?? "https://oidc-bridge.did.md").replace(/\/$/, "");
const port = Number(process.env.PORT ?? 8790);
const dataDir = process.env.DATA_DIR ?? "./data/oidc-bridge";
// DITO_* is canonical; DISPO_* kept as aliases so older unit files and docs keep working.
const ditoIssuer = (process.env.DITO_ISSUER ?? process.env.DISPO_ISSUER ?? "https://api.did.md").replace(/\/$/, "");
const ditoAuthEndpoint =
  process.env.DITO_AUTHORIZATION_ENDPOINT ??
  process.env.DISPO_AUTHORIZATION_ENDPOINT ??
  "https://app.did.md/authorize";
const walletIdentityDomain = (process.env.WALLET_IDENTITY_DOMAIN ?? "did.md").toLowerCase();
// PLAN6: when set, oidc-bridge authenticates to dito as a did:webvh RP
// (JAR) instead of a DCR-registered client. Unset by default -- existing
// deployments keep working on the DCR path until this is explicitly
// provisioned (see scripts/create-rp-did.ts in the did.md repo).
const rpDidKeyFile = process.env.RP_DID_KEY_FILE;
// PLAN8: dito posts
// vp_token/id_token straight here (response_mode=direct_post) instead of
// oidc-bridge exchanging a `code` at api.did.md -- only meaningful
// alongside rpDidKeyFile (see DitoClient.directPostAuthorizationUrl).
// Deliberately requires its OWN explicit env var rather than defaulting
// from rpDidKeyFile's mere presence: production already runs with
// RP_DID_KEY_FILE set (from PLAN6) without yet publishing this response_uri
// in the RP's DID document `service` array (dito's jarAuthorizationParameters
// checks this the same way it checks redirect_uri) -- an implicit default
// here would flip every live login to direct_post, and fail outright,
// the moment this binary deploys, before that publish step (a separate,
// manual provisioning action) has happened. Set this only after publishing.
const rpResponseUri = process.env.RP_RESPONSE_URI;
const dito = new DitoClient(ditoIssuer, `${issuer}/callback`, `${dataDir}/dito-registration.json`, ditoAuthEndpoint, walletIdentityDomain, rpDidKeyFile, rpResponseUri);
// PLAN8: the browser (app.did.md) POSTs directly to /authorize/direct-callback
// below -- unlike every other route here, that request's Origin is not this
// bridge's own client, so it needs an explicit CORS allow.
const APP_ORIGIN = "https://app.did.md";
function directCallbackCors(): HeadersInit { return { "access-control-allow-origin": APP_ORIGIN, "access-control-allow-methods": "POST", "access-control-allow-headers": "content-type", vary: "origin" }; }
// PLAN6: oidc-bridge.did.md is a single reverse-proxied Node process (unlike
// t.biset.md's static file_server), so its own did:webvh log -- the public
// counterpart of rpDidKeyFile above, letting did.md's server resolve this
// RP's identity -- has to be served by a route here rather than dropped in
// as a static file. Unset (like rpDidKeyFile) until this RP DID is actually
// provisioned; /.well-known/did.jsonl 404s until then, same as before this
// route existed.
const rpDidLogFile = process.env.RP_DID_LOG_FILE;

const clientsPath =
  process.env.CLIENTS_CONFIG ??
  process.env.FORGEJO_CLIENT_CONFIG ??
  "server/oauth/config/forgejo-client.json";

// Any number of relying parties (Forgejo, Outline, Hi.Events, ...) share this
// bridge. The file holds one client object or an array of them. Clients are
// re-read from disk on each authorize/token so adding an RP in
// /etc/did-md/oidc-clients.json does not require a service restart.
function loadClients(): Map<string, Client> {
  const raw = JSON.parse(readFileSync(clientsPath, "utf8"));
  const list = Array.isArray(raw) ? raw : [raw];
  const clients = new Map<string, Client>();
  for (const c of list) {
    if (!c?.client_id || !c?.client_secret || !Array.isArray(c.redirect_uris)) {
      throw new Error(`invalid client config: ${JSON.stringify(c?.client_id)}`);
    }
    clients.set(c.client_id, c);
  }
  if (clients.size === 0) throw new Error("no OIDC clients configured");
  return clients;
}

let clients = loadClients();
let clientsLoadedAt = Date.now();
const CLIENTS_RELOAD_MS = 15_000;

function getClients(): Map<string, Client> {
  if (Date.now() - clientsLoadedAt >= CLIENTS_RELOAD_MS) {
    try {
      clients = loadClients();
    } catch (err) {
      // Keep serving the last good map if the file is mid-write or invalid.
      console.error("client config reload failed:", err);
    }
    clientsLoadedAt = Date.now();
  }
  return clients;
}

const keys = new BridgeKeys(`${dataDir}/signing-key.pem`);
const sessions = new SessionStore<BridgeSession>();
const codes = new Map<string, Code>();
const accessTokens = new Map<string, AccessToken>();

// Expired entries are only ever read as "not found" (see /token and
// /userinfo), so this periodic sweep is just to stop both maps growing
// forever -- it is not load-bearing for correctness.
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of accessTokens) if (value.expiresAt <= now) accessTokens.delete(key);
  for (const [key, value] of codes) if (value.expiresAt <= now) codes.delete(key);
}, 60_000).unref();

function error(message: string, status = 400) {
  return new Response(JSON.stringify({ error: "invalid_request", error_description: message }), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}
function redirect(uri: string, params: Record<string, string>) {
  const url = new URL(uri);
  for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
  return Response.redirect(url, 302);
}
function basic(request: Request) {
  const value = request.headers.get("authorization");
  if (!value?.startsWith("Basic ")) return;
  try {
    const [id, secret] = Buffer.from(value.slice(6), "base64").toString().split(":");
    return { id: decodeURIComponent(id!), secret: decodeURIComponent(secret!) };
  } catch {}
}
function bearerToken(request: Request, url: URL) {
  const value = request.headers.get("authorization");
  if (value?.startsWith("Bearer ")) return value.slice(7).trim();
  return url.searchParams.get("access_token") ?? "";
}

// PLAN10: did.md's own api.did.md clients (biset's device-refresh, any
// future DCR client) and oidc-bridge's own downstream RPs (Forgejo et al.)
// both publish a discovery document at this exact well-known path, under
// different hostnames -- the one ambiguity between the two merged route
// sets, disambiguated by Host the same way Caddy already routes these two
// hostnames to (previously) two different processes.
const API_DID_MD_HOST = "api.did.md";
function requestHost(request: Request): string {
  return (request.headers.get("host") ?? "").split(":")[0]?.toLowerCase() ?? "";
}

async function handleRoute(request: Request): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname === "/healthz") return new Response("ok\n");
  // PLAN10 merge dropped did-md-server's own global OPTIONS short-circuit
  // (server/server.ts, decommissioned) -- oauthFetch's routes only match
  // GET/POST/DELETE, so a bare preflight on e.g. /v1/oauth/device-refresh
  // fell through to the plain 404 below with no CORS headers at all,
  // surfacing live as biset's device-refresh "Failed to fetch" on reload
  // (2026-09-23).
  if (request.method === "OPTIONS" && url.pathname.startsWith("/v1/oauth/")) {
    return new Response(null, { status: 204, headers: oauthCors(request) });
  }
  if (url.pathname === "/.well-known/openid-configuration" && requestHost(request) === API_DID_MD_HOST) {
    const response = await oauthFetch(request, url);
    return response ?? new Response("not found\n", { status: 404 });
  }
  if (url.pathname === "/.well-known/openid-configuration") {
    return Response.json({
      issuer,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      userinfo_endpoint: `${issuer}/userinfo`,
      jwks_uri: `${issuer}/jwks`,
      response_types_supported: ["code"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      scopes_supported: ["openid", "profile", "email"],
      token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
      code_challenge_methods_supported: ["S256"],
    });
  }
  if (url.pathname === "/jwks") {
    return Response.json(keys.jwks(), { headers: { "cache-control": "public, max-age=300" } });
  }
  if (url.pathname === "/.well-known/did.jsonl") {
    // A did:webvh log is a public document meant to be resolved from any
    // origin (see did.md's own server.ts publicDocumentCors) -- without
    // this, a browser fetch() of this URL from a different origin (e.g.
    // app.did.md verifying this RP's JAR signature) fails outright with a
    // network error, not merely an unreadable response.
    const headers = { "content-type": "text/jsonl; charset=utf-8", "access-control-allow-origin": "*" };
    if (!rpDidLogFile) return new Response("not found\n", { status: 404, headers });
    try { return new Response(readFileSync(rpDidLogFile, "utf8"), { headers }); }
    catch { return new Response("not found\n", { status: 404, headers }); }
  }

  const activeClients = getClients();

  if (url.pathname === "/authorize" && request.method === "GET") {
    const p = url.searchParams;
    const client = activeClients.get(p.get("client_id") ?? "");
    if (p.get("response_type") !== "code" || !client) return error("unknown client or response type");
    const redirectUri = p.get("redirect_uri") ?? "";
    if (!client.redirect_uris.includes(redirectUri)) return error("redirect_uri is not allowed");
    const state = p.get("state");
    const nonce = p.get("nonce") ?? undefined;
    const challenge = p.get("code_challenge");
    if (!state || !challenge || p.get("code_challenge_method") !== "S256") {
      return error("state and S256 PKCE are required");
    }
    // PLAN8: direct_post only once RP_RESPONSE_URI is explicitly set (see
    // its own comment above) -- an RP-DID client with no response_uri yet
    // still uses the original JAR+code+PKCE round trip against api.did.md,
    // same as today. See session-store.ts's own comment on why exactly one
    // of bridgePkceVerifier/ditoNonce is set here.
    if (dito.isRpDid && rpResponseUri) {
      const ditoNonce = randomBase64url(32);
      const id = sessions.create({ clientId: client.client_id, redirectUri, state, nonce, pkceChallenge: challenge, ditoNonce });
      // The application's own name if its client entry has one, else its host (what the person recognises).
      const appName = (typeof (client as { client_name?: unknown }).client_name === "string" && (client as { client_name: string }).client_name.trim()) || new URL(redirectUri).host;
      return redirect(dito.directPostAuthorizationUrl(id, ditoNonce, { name: appName, uri: new URL(redirectUri).origin }), {});
    }
    const verifier = randomBase64url(48);
    const id = sessions.create({
      clientId: client.client_id,
      redirectUri,
      state,
      nonce,
      pkceChallenge: challenge,
      bridgePkceVerifier: verifier,
    });
    return redirect(await dito.authorizationUrl(id, verifier), {});
  }

  // PLAN8: dito's own browser POSTs here directly (response_mode=
  // direct_post) instead of redirecting back with a `code` -- see
  // DitoClient.directPostAuthorizationUrl/verifyDirectPost. Mints the same
  // downstream-RP code /callback used to, then hands back the final
  // redirect_uri in the response body per the OID4VP direct_post contract
  // (the wallet's browser navigates there itself; no extra hop needed).
  if (url.pathname === "/authorize/direct-callback" && request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: directCallbackCors() });
  }
  if (url.pathname === "/authorize/direct-callback" && request.method === "POST") {
    const headers = directCallbackCors();
    const form = new URLSearchParams(await request.text());
    const id = form.get("state") ?? "";
    const session = sessions.take(id);
    if (!session || session.ditoNonce === undefined) return new Response(JSON.stringify({ error: "invalid_request", error_description: "callback state is invalid" }), { status: 400, headers: { ...headers, "content-type": "application/json" } });
    const idToken = form.get("id_token");
    const requestError = form.get("error");
    if (requestError) return new Response(JSON.stringify({ error: "access_denied", error_description: form.get("error_description") ?? requestError }), { status: 400, headers: { ...headers, "content-type": "application/json" } });
    if (!idToken) return new Response(JSON.stringify({ error: "invalid_request", error_description: "id_token is required" }), { status: 400, headers: { ...headers, "content-type": "application/json" } });
    try {
      const verified = await dito.verifyDirectPost(idToken, session.ditoNonce);
      session.verifiedClaims = verified.claims;
      const bridgeCode = randomBase64url(32);
      codes.set(bridgeCode, { session, expiresAt: Date.now() + 2 * 60_000 });
      const redirectUri = new URL(session.redirectUri);
      redirectUri.searchParams.set("code", bridgeCode);
      redirectUri.searchParams.set("state", session.state);
      return Response.json({ redirect_uri: redirectUri.toString() }, { headers });
    } catch (cause) {
      return new Response(JSON.stringify({ error: "server_error", error_description: cause instanceof Error ? cause.message : "upstream verification failed" }), { status: 502, headers: { ...headers, "content-type": "application/json" } });
    }
  }

  if (url.pathname === "/callback" && request.method === "GET") {
    const id = url.searchParams.get("state") ?? "";
    const code = url.searchParams.get("code");
    const session = sessions.take(id);
    // A PLAN8 direct_post session (bridgePkceVerifier unset, see
    // session-store.ts) never reaches this route -- dito posts its
    // response straight to /authorize/direct-callback instead of
    // redirecting back with a `code` -- but the type only knows
    // "optional", so this still has to be checked explicitly.
    if (!session || !code || session.bridgePkceVerifier === undefined) return error("callback state or code is invalid");
    try {
      const verified = await dito.exchange(code, session.bridgePkceVerifier);
      session.verifiedClaims = verified.claims;
      const bridgeCode = randomBase64url(32);
      codes.set(bridgeCode, { session, expiresAt: Date.now() + 2 * 60_000 });
      return redirect(session.redirectUri, { code: bridgeCode, state: session.state });
    } catch (cause) {
      return error(cause instanceof Error ? cause.message : "upstream verification failed", 502);
    }
  }

  if (url.pathname === "/token" && request.method === "POST") {
    const form = new URLSearchParams(await request.text());
    const credentials = basic(request);
    const clientId = credentials?.id ?? form.get("client_id");
    const secret = credentials?.secret ?? form.get("client_secret");
    const client = activeClients.get(clientId ?? "");
    if (!client || secret !== client.client_secret || form.get("grant_type") !== "authorization_code") {
      return error("client authentication failed", 401);
    }
    const code = form.get("code") ?? "";
    const stored = codes.get(code);
    codes.delete(code);
    if (!stored || stored.expiresAt <= Date.now()) return error("authorization code is invalid or expired");
    if (form.get("redirect_uri") !== stored.session.redirectUri) return error("redirect_uri mismatch");
    const verifier = form.get("code_verifier") ?? "";
    const challenge = await pkceChallenge(verifier);
    if (challenge !== stored.session.pkceChallenge) return error("PKCE verification failed");
    const now = Math.floor(Date.now() / 1000);
    const source = stored.session.verifiedClaims ?? {};
    const accessToken = randomBase64url(32);
    const claims = {
      ...source,
      iss: issuer,
      aud: client.client_id,
      sub: source.sub,
      ...(stored.session.nonce ? { nonce: stored.session.nonce } : {}),
      iat: now,
      exp: now + 300,
    };
    accessTokens.set(accessToken, { claims, expiresAt: Date.now() + 300_000 });
    return Response.json(
      { access_token: accessToken, token_type: "Bearer", expires_in: 300, id_token: keys.jwt(claims) },
      { headers: { "cache-control": "no-store" } },
    );
  }

  if (url.pathname === "/userinfo") {
    const token = bearerToken(request, url);
    const entry = accessTokens.get(token);
    if (!entry || entry.expiresAt <= Date.now()) {
      if (entry) accessTokens.delete(token);
      return Response.json({ error: "invalid_token" }, { status: 401 });
    }
    const c = entry.claims as Record<string, unknown>;
    const body = {
      sub: c.sub,
      ...(c.email ? { email: c.email } : {}),
      ...(c.email_verified !== undefined ? { email_verified: c.email_verified } : {}),
      ...(c.name ? { name: c.name } : {}),
      ...(c.preferred_username ? { preferred_username: c.preferred_username } : {}),
      ...(c.picture ? { picture: c.picture } : {}),
      ...(c.locale ? { locale: c.locale } : {}),
    };
    return Response.json(body, { headers: { "cache-control": "no-store" } });
  }

  // PLAN10: everything oauth-server.ts owns (`/v1/oauth/*`,
  // `/.well-known/oauth-authorization-server`) -- disjoint from every path
  // above, so this is a plain fallback, not a Host check like the
  // discovery-document special case above.
  const oauthResponse = await oauthFetch(request, url);
  if (oauthResponse) return oauthResponse;

  return new Response("not found\n", { status: 404 });
}

// PLAN10: the same rationale as did-md-server's own `fail()`
// (server/server.ts) -- a thrown Invalid from an oauth-server.ts route
// function must become a proper, CORS'd 400 JSON response, not an
// uncaught exception reaching Node's generic error page. Without this, a
// browser caller (biset's device-refresh -- see server/server.ts's own
// comment on the exact "Failed to fetch" bug this once caused live) gets
// an uncatchable network error instead of a readable body. Confirmed live
// 2026-09-22: merging oauthFetch into this file without also carrying this
// wrapper over reintroduced that exact bug (POST /v1/oauth/device-refresh
// with a malformed body crashed instead of returning 400) before this fix.
export async function handle(request: Request): Promise<Response> {
  try {
    return await handleRoute(request);
  } catch (caught) {
    const status = caught instanceof Invalid ? 400 : 500;
    const message = caught instanceof Invalid ? caught.message : "internal error";
    console.error(caught);
    const pathname = (() => { try { return new URL(request.url).pathname; } catch { return ""; } })();
    const oauthPath = pathname.startsWith("/v1/oauth/") || pathname.startsWith("/.well-known/oauth-authorization-server") || pathname.startsWith("/.well-known/openid-configuration");
    return new Response(JSON.stringify({ error: "invalid_request", error_description: message }), {
      status, headers: { ...(oauthPath ? oauthCors(request) : {}), "content-type": "application/json", "cache-control": "no-store" },
    });
  }
}

if (import.meta.main) {
  await dito.initialize();
  const active = getClients();
  serve({ hostname: process.env.HOST ?? "127.0.0.1", port, fetch: handle });
  console.log(`OIDC bridge listening on ${port}`);
  console.log(`clients: ${[...active.keys()].join(", ")}`);
  console.log(`clients_config: ${clientsPath}`);
}
