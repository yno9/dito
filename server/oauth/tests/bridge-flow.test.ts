import { afterAll, expect, test } from "bun:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { createPublicKey, verify } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = new URL("../../..", import.meta.url).pathname; const temporary = mkdtempSync(join(tmpdir(), "did-md-bridge-"));
const upstreamPort = 20_000 + Math.floor(Math.random() * 5000), bridgePort = upstreamPort + 5000;
const upstreamBase = `http://127.0.0.1:${upstreamPort}`, bridgeBase = `http://127.0.0.1:${bridgePort}`;
const forgejoRedirect = "http://127.0.0.1:3999/callback"; const forgejoSecret = "test-client-secret"; const upstreamClientId = "bridge-test-client";
const widgetRedirect = "http://127.0.0.1:3998/callback"; const widgetSecret = "widget-client-secret";
const walletKey = ed25519.utils.randomSecretKey();

function walletToken(aud: string, extra: Record<string, unknown> = {}) { const jwk = { kty: "OKP", crv: "Ed25519", x: Buffer.from(ed25519.getPublicKey(walletKey)).toString("base64url") }; const header = Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "JWT", kid: "did:webvh:test#pass-1", jwk })).toString("base64url"); const now = Math.floor(Date.now() / 1000); const payload = Buffer.from(JSON.stringify({ iss: "did:webvh:test", sub: "ignored", aud, iat: now, exp: now + 300, preferred_username: "alice", ...extra })).toString("base64url"); return `${header}.${payload}.${Buffer.from(ed25519.sign(new TextEncoder().encode(`${header}.${payload}`), walletKey)).toString("base64url")}`; }
function base64urlJson(part: string) { return JSON.parse(Buffer.from(part, "base64url").toString()); }
let requestedAudience = upstreamClientId;
const upstream = Bun.serve({ port: upstreamPort, fetch: async request => { const url = new URL(request.url); if (url.pathname === "/v1/oauth/register") return Response.json({ client_id: upstreamClientId }, { status: 201 }); if (url.pathname === "/v1/oauth/token") return Response.json({ id_token: walletToken(requestedAudience) }); return new Response("not found", { status: 404 }); } });
// An array of clients -- this is what proves the bridge is multi-client, not
// just tolerant of a stray extra field on a single-client config.
writeFileSync(join(temporary, "forgejo.json"), JSON.stringify([
  { client_id: "forgejo", client_secret: forgejoSecret, redirect_uris: [forgejoRedirect] },
  { client_id: "widget", client_secret: widgetSecret, redirect_uris: [widgetRedirect] },
]));
const bridge = Bun.spawn({ cmd: [process.execPath, "server/oauth/src/server.ts"], cwd: root, env: { ...process.env, PORT: String(bridgePort), DATA_DIR: join(temporary, "data"), BRIDGE_ISSUER: bridgeBase, DITO_ISSUER: upstreamBase, DITO_AUTHORIZATION_ENDPOINT: `${upstreamBase}/authorize`, FORGEJO_CLIENT_CONFIG: join(temporary, "forgejo.json") }, stdout: "ignore", stderr: "ignore" });
async function ready() { for (let i = 0; i < 100; i++) { try { if ((await fetch(`${bridgeBase}/healthz`)).ok) return; } catch {} await Bun.sleep(20); } throw new Error("bridge did not start"); }
afterAll(async () => { bridge.kill(); await bridge.exited; upstream.stop(true); rmSync(temporary, { recursive: true, force: true }); });

test("full Forgejo -> bridge -> dito -> bridge token flow", async () => {
  await ready(); const forgejoVerifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"; const forgejoChallenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(forgejoVerifier))).toString("base64url");
  const authorize = new URL(`${bridgeBase}/authorize`); authorize.search = new URLSearchParams({ response_type: "code", client_id: "forgejo", redirect_uri: forgejoRedirect, scope: "openid profile", state: "forgejo-state", nonce: "forgejo-nonce", code_challenge: forgejoChallenge, code_challenge_method: "S256" }).toString();
  const first = await fetch(authorize, { redirect: "manual" }); const upstreamUrl = new URL(first.headers.get("location")!); expect(upstreamUrl.origin + upstreamUrl.pathname).toBe(`${upstreamBase}/authorize`); expect(upstreamUrl.searchParams.get("code_challenge")).not.toBe(forgejoChallenge);
  const callback = await fetch(`${bridgeBase}/callback?code=dito-code&state=${encodeURIComponent(upstreamUrl.searchParams.get("state")!)}`, { redirect: "manual" }); const forgejoUrl = new URL(callback.headers.get("location")!); expect(forgejoUrl.searchParams.get("state")).toBe("forgejo-state");
  const form = new URLSearchParams({ grant_type: "authorization_code", code: forgejoUrl.searchParams.get("code")!, redirect_uri: forgejoRedirect, code_verifier: forgejoVerifier }); const tokenResponse = await fetch(`${bridgeBase}/token`, { method: "POST", headers: { authorization: `Basic ${Buffer.from(`forgejo:${forgejoSecret}`).toString("base64")}`, "content-type": "application/x-www-form-urlencoded" }, body: form }); expect(tokenResponse.status).toBe(200); const tokens = await tokenResponse.json();
  const [header, payload, signature] = tokens.id_token.split("."); const claims = JSON.parse(Buffer.from(payload, "base64url").toString()); expect(claims).toMatchObject({ iss: bridgeBase, aud: "forgejo", nonce: "forgejo-nonce", preferred_username: "alice" }); expect(claims.sub).toHaveLength(43);
  const jwks = await (await fetch(`${bridgeBase}/jwks`)).json(); expect(verify("RSA-SHA256", Buffer.from(`${header}.${payload}`), createPublicKey({ key: jwks.keys[0], format: "jwk" }), Buffer.from(signature, "base64url"))).toBe(true);
});

test("a second, independently configured client completes its own flow and can call /userinfo", async () => {
  await ready(); const verifier = "widgetverifierabcdefghijklmnopqrstuvwxyzABCDEFG"; const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");
  const authorize = new URL(`${bridgeBase}/authorize`); authorize.search = new URLSearchParams({ response_type: "code", client_id: "widget", redirect_uri: widgetRedirect, scope: "openid profile", state: "widget-state", code_challenge: challenge, code_challenge_method: "S256" }).toString();
  const first = await fetch(authorize, { redirect: "manual" }); const upstreamUrl = new URL(first.headers.get("location")!);
  const callback = await fetch(`${bridgeBase}/callback?code=dito-code&state=${encodeURIComponent(upstreamUrl.searchParams.get("state")!)}`, { redirect: "manual" }); const widgetUrl = new URL(callback.headers.get("location")!); expect(widgetUrl.origin + widgetUrl.pathname).toBe(widgetRedirect); expect(widgetUrl.searchParams.get("state")).toBe("widget-state");
  const form = new URLSearchParams({ grant_type: "authorization_code", code: widgetUrl.searchParams.get("code")!, redirect_uri: widgetRedirect, code_verifier: verifier });
  const tokenResponse = await fetch(`${bridgeBase}/token`, { method: "POST", headers: { authorization: `Basic ${Buffer.from(`widget:${widgetSecret}`).toString("base64")}`, "content-type": "application/x-www-form-urlencoded" }, body: form });
  expect(tokenResponse.status).toBe(200); const tokens = await tokenResponse.json();
  const claims = JSON.parse(Buffer.from(tokens.id_token.split(".")[1], "base64url").toString()); expect(claims.aud).toBe("widget"); expect(claims.preferred_username).toBe("alice");
  // A token minted for "widget" must not silently work against another
  // client's config -- there's only one bridge-wide access token map, so
  // this mostly confirms /userinfo doesn't need the caller to also present
  // its client_id.
  const userinfo = await fetch(`${bridgeBase}/userinfo`, { headers: { authorization: `Bearer ${tokens.access_token}` } });
  expect(userinfo.status).toBe(200); const info = await userinfo.json();
  expect(info).toMatchObject({ sub: claims.sub, preferred_username: "alice" });
  expect(info.aud).toBeUndefined();
  const rejected = await fetch(`${bridgeBase}/userinfo`, { headers: { authorization: "Bearer not-a-real-token" } });
  expect(rejected.status).toBe(401);
});

test("accepts an authorize request with no nonce, as Forgejo actually sends", async () => {
  // Regression: OIDC Core 3.1.2.1 only REQUIRES nonce for implicit/hybrid
  // flows -- Forgejo's real authorization-code request omits it entirely,
  // and the bridge used to hard-require it, breaking every real login.
  await ready(); const verifier = "zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJI"; const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");
  const authorize = new URL(`${bridgeBase}/authorize`); authorize.search = new URLSearchParams({ response_type: "code", client_id: "forgejo", redirect_uri: forgejoRedirect, state: "no-nonce-state", code_challenge: challenge, code_challenge_method: "S256" }).toString();
  const first = await fetch(authorize, { redirect: "manual" }); expect(first.status).toBe(302);
  const upstreamUrl = new URL(first.headers.get("location")!);
  const callback = await fetch(`${bridgeBase}/callback?code=dito-code&state=${encodeURIComponent(upstreamUrl.searchParams.get("state")!)}`, { redirect: "manual" }); const forgejoUrl = new URL(callback.headers.get("location")!);
  const form = new URLSearchParams({ grant_type: "authorization_code", code: forgejoUrl.searchParams.get("code")!, redirect_uri: forgejoRedirect, code_verifier: verifier });
  const tokenResponse = await fetch(`${bridgeBase}/token`, { method: "POST", headers: { authorization: `Basic ${Buffer.from(`forgejo:${forgejoSecret}`).toString("base64")}`, "content-type": "application/x-www-form-urlencoded" }, body: form });
  expect(tokenResponse.status).toBe(200);
  const claims = JSON.parse(Buffer.from((await tokenResponse.json()).id_token.split(".")[1], "base64url").toString());
  expect(claims.nonce).toBeUndefined();
});

test("rejects an upstream id_token with the wrong audience", async () => {
  requestedAudience = "someone-else"; const verifier = "mnopqrstuvwxyzABCDEFGHIJKLMNopqrstuvwxyzABCDE"; const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url"); const authorize = new URL(`${bridgeBase}/authorize`); authorize.search = new URLSearchParams({ response_type: "code", client_id: "forgejo", redirect_uri: forgejoRedirect, state: "s2", nonce: "n2", code_challenge: challenge, code_challenge_method: "S256" }).toString(); const first = await fetch(authorize, { redirect: "manual" }); const state = new URL(first.headers.get("location")!).searchParams.get("state"); const callback = await fetch(`${bridgeBase}/callback?code=x&state=${state}`); expect(callback.status).toBe(502); requestedAudience = upstreamClientId;
});

// PLAN6: oidc-bridge.did.md is a single reverse-proxied process, so its own
// did:webvh log (the public counterpart of RP_DID_KEY_FILE, letting did.md's
// server resolve this RP's identity when it authenticates via JAR) has to be
// served by a route here instead of dropped in as a static file next to the
// app, unlike t.biset.md. Unconfigured by default -- see this test server's
// spawn env (no RP_DID_LOG_FILE), matching a real deployment before this RP
// DID is provisioned.
test("GET /.well-known/did.jsonl is 404 until RP_DID_LOG_FILE is configured", async () => {
  await ready();
  const response = await fetch(`${bridgeBase}/.well-known/did.jsonl`);
  expect(response.status).toBe(404);
  // A did:webvh log is a public document resolved from any origin (e.g.
  // app.did.md verifying this RP's JAR signature) -- CORS must be open even
  // on the 404, or a browser fetch() fails with a network error before the
  // caller ever sees the 404 status to react to.
  expect(response.headers.get("access-control-allow-origin")).toBe("*");
});

test("GET /.well-known/did.jsonl serves the configured RP DID log verbatim", async () => {
  const logFile = join(temporary, "rp-did.jsonl");
  writeFileSync(logFile, '{"versionId":"1-fake","state":{"id":"did:webvh:fake:oidc-bridge.did.md"}}\n');
  const dedicatedPort = bridgePort + 1000;
  const dedicated = Bun.spawn({
    cmd: [process.execPath, "server/oauth/src/server.ts"], cwd: root,
    env: { ...process.env, PORT: String(dedicatedPort), DATA_DIR: join(temporary, "data-log"), BRIDGE_ISSUER: `http://127.0.0.1:${dedicatedPort}`, DITO_ISSUER: upstreamBase, DITO_AUTHORIZATION_ENDPOINT: `${upstreamBase}/authorize`, FORGEJO_CLIENT_CONFIG: join(temporary, "forgejo.json"), RP_DID_LOG_FILE: logFile },
    stdout: "ignore", stderr: "ignore",
  });
  try {
    for (let i = 0; i < 100; i++) { try { if ((await fetch(`http://127.0.0.1:${dedicatedPort}/healthz`)).ok) break; } catch {} await Bun.sleep(20); }
    const response = await fetch(`http://127.0.0.1:${dedicatedPort}/.well-known/did.jsonl`);
    expect(response.status).toBe(200);
    expect(await response.text()).toBe('{"versionId":"1-fake","state":{"id":"did:webvh:fake:oidc-bridge.did.md"}}\n');
    expect(response.headers.get("access-control-allow-origin")).toBe("*");
  } finally {
    dedicated.kill(); await dedicated.exited;
  }
});

// PLAN8: with an RP DID key
// AND an explicit RP_RESPONSE_URI configured, oidc-bridge's own leg to
// dito switches from code+token to direct_post -- these tests spawn a
// second bridge instance with both set instead of adding a third mode to
// the shared instance above, since DitoClient.isRpDid is fixed for a
// process's whole lifetime.
{
  const rpDid = "did:webvh:zRpTestOnlyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:oidc-bridge.example";
  const rpPrivateKey = ed25519.utils.randomSecretKey();
  const rpKeyFile = join(temporary, "rp-did-key.json");
  writeFileSync(rpKeyFile, JSON.stringify({ did: rpDid, verificationMethod: `${rpDid}#pass-1`, privateKey: Buffer.from(rpPrivateKey).toString("base64url") }));
  const directPort = bridgePort + 2000;
  const directBase = `http://127.0.0.1:${directPort}`;
  const directBridge = Bun.spawn({
    cmd: [process.execPath, "server/oauth/src/server.ts"], cwd: root,
    env: { ...process.env, PORT: String(directPort), DATA_DIR: join(temporary, "data-direct"), BRIDGE_ISSUER: directBase, DITO_ISSUER: upstreamBase, DITO_AUTHORIZATION_ENDPOINT: `${upstreamBase}/authorize`, FORGEJO_CLIENT_CONFIG: join(temporary, "forgejo.json"), RP_DID_KEY_FILE: rpKeyFile, RP_RESPONSE_URI: `${directBase}/authorize/direct-callback` },
    stdout: "ignore", stderr: "ignore",
  });
  async function directReady() { for (let i = 0; i < 100; i++) { try { if ((await fetch(`${directBase}/healthz`)).ok) return; } catch {} await Bun.sleep(20); } throw new Error("direct_post bridge did not start"); }
  afterAll(async () => { directBridge.kill(); await directBridge.exited; });

  test("PLAN8: an RP-DID-configured bridge sends a direct_post JAR request, not code+PKCE", async () => {
    await directReady();
    const authorize = new URL(`${directBase}/authorize`); authorize.search = new URLSearchParams({ response_type: "code", client_id: "forgejo", redirect_uri: forgejoRedirect, scope: "openid profile", state: "direct-state-1", code_challenge: "A".repeat(43), code_challenge_method: "S256" }).toString();
    const first = await fetch(authorize, { redirect: "manual" });
    const ditoUrl = new URL(first.headers.get("location")!);
    expect(ditoUrl.searchParams.get("client_id")).toBe(rpDid);
    expect(ditoUrl.searchParams.get("response_type")).toBe("vp_token id_token");
    const jwt = ditoUrl.searchParams.get("request")!;
    const payload = base64urlJson(jwt.split(".")[1]!);
    expect(payload).toMatchObject({ iss: rpDid, client_id: rpDid, client_id_scheme: "did", response_type: "vp_token id_token", response_mode: "direct_post", response_uri: `${directBase}/authorize/direct-callback` });
    expect(payload.code_challenge).toBeUndefined();
    expect(payload.redirect_uri).toBeUndefined();
    expect(typeof payload.nonce).toBe("string");
    expect(payload.nonce.length).toBeGreaterThan(0);
    // The downstream app, as the bridge asserts it inside its signed request: a name (its host
    // when its config has none) and its home, so the wallet can show name, domain and "via".
    const home = new URL(forgejoRedirect);
    expect(payload.client_metadata).toEqual({ client_name: home.host, client_uri: home.origin });
  });

  test("PLAN8: POSTing a valid id_token to /authorize/direct-callback completes the downstream flow", async () => {
    await directReady();
    const forgejoVerifier = "direct2verifierabcdefghijklmnopqrstuvwxyzABCD"; const forgejoChallenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(forgejoVerifier))).toString("base64url");
    const authorize = new URL(`${directBase}/authorize`); authorize.search = new URLSearchParams({ response_type: "code", client_id: "forgejo", redirect_uri: forgejoRedirect, scope: "openid profile", state: "direct-state-2", code_challenge: forgejoChallenge, code_challenge_method: "S256" }).toString();
    const first = await fetch(authorize, { redirect: "manual" });
    const ditoUrl = new URL(first.headers.get("location")!);
    const payload = base64urlJson(ditoUrl.searchParams.get("request")!.split(".")[1]!);
    const idToken = walletToken(rpDid, { nonce: payload.nonce });
    const direct = await fetch(`${directBase}/authorize/direct-callback`, {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", origin: "https://app.did.md" },
      body: new URLSearchParams({ vp_token: JSON.stringify({ capability: [] }), id_token: idToken, state: payload.state }),
    });
    expect(direct.status).toBe(200);
    expect(direct.headers.get("access-control-allow-origin")).toBe("https://app.did.md");
    const { redirect_uri } = await direct.json() as { redirect_uri: string };
    const forgejoUrl = new URL(redirect_uri);
    expect(forgejoUrl.origin + forgejoUrl.pathname).toBe(forgejoRedirect);
    expect(forgejoUrl.searchParams.get("state")).toBe("direct-state-2");
    const bridgeCode = forgejoUrl.searchParams.get("code")!;
    const form = new URLSearchParams({ grant_type: "authorization_code", code: bridgeCode, redirect_uri: forgejoRedirect, code_verifier: forgejoVerifier });
    const tokenResponse = await fetch(`${directBase}/token`, { method: "POST", headers: { authorization: `Basic ${Buffer.from(`forgejo:${forgejoSecret}`).toString("base64")}`, "content-type": "application/x-www-form-urlencoded" }, body: form });
    expect(tokenResponse.status).toBe(200);
    const claims = base64urlJson((await tokenResponse.json()).id_token.split(".")[1]);
    expect(claims).toMatchObject({ aud: "forgejo", preferred_username: "alice" });
  });

  test("PLAN8: /authorize/direct-callback rejects an id_token whose nonce does not match", async () => {
    await directReady();
    const authorize = new URL(`${directBase}/authorize`); authorize.search = new URLSearchParams({ response_type: "code", client_id: "forgejo", redirect_uri: forgejoRedirect, scope: "openid profile", state: "direct-state-3", code_challenge: "C".repeat(43), code_challenge_method: "S256" }).toString();
    const first = await fetch(authorize, { redirect: "manual" });
    const ditoUrl = new URL(first.headers.get("location")!);
    const payload = base64urlJson(ditoUrl.searchParams.get("request")!.split(".")[1]!);
    const idToken = walletToken(rpDid, { nonce: "the-wrong-nonce" });
    const direct = await fetch(`${directBase}/authorize/direct-callback`, {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", origin: "https://app.did.md" },
      body: new URLSearchParams({ vp_token: JSON.stringify({ capability: [] }), id_token: idToken, state: payload.state }),
    });
    expect(direct.status).toBe(502);
    expect((await direct.json()).error_description).toContain("nonce");
  });

  test("PLAN8: OPTIONS preflight on /authorize/direct-callback carries CORS for app.did.md", async () => {
    await directReady();
    const preflight = await fetch(`${directBase}/authorize/direct-callback`, { method: "OPTIONS", headers: { origin: "https://app.did.md" } });
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get("access-control-allow-origin")).toBe("https://app.did.md");
    expect(preflight.headers.get("access-control-allow-methods")).toBe("POST");
  });
}

// PLAN8 regression: production already runs with RP_DID_KEY_FILE set (from
// PLAN6) and does NOT yet publish a direct_post response_uri in its DID
// document -- deploying this code must not silently flip that deployment to
// direct_post (which would fail outright at dito, since the unpublished
// response_uri fails jarAuthorizationParameters' service-array check) until
// RP_RESPONSE_URI is deliberately set as a separate step. This is the exact
// gap a background security/correctness review would otherwise miss, since
// nothing here is a vulnerability -- it's a same-process behavior change
// gated on the wrong signal.
{
  const rpDid = "did:webvh:zRpNoResponseUriYetXXXXXXXXXXXXXXXXXXXXXXXX:oidc-bridge.example";
  const rpPrivateKey = ed25519.utils.randomSecretKey();
  const rpKeyFile = join(temporary, "rp-did-key-no-response-uri.json");
  writeFileSync(rpKeyFile, JSON.stringify({ did: rpDid, verificationMethod: `${rpDid}#pass-1`, privateKey: Buffer.from(rpPrivateKey).toString("base64url") }));
  const transitionPort = bridgePort + 3000;
  const transitionBase = `http://127.0.0.1:${transitionPort}`;
  const transitionBridge = Bun.spawn({
    cmd: [process.execPath, "server/oauth/src/server.ts"], cwd: root,
    // Deliberately no RP_RESPONSE_URI -- this is the actual shape of
    // today's production env file.
    env: { ...process.env, PORT: String(transitionPort), DATA_DIR: join(temporary, "data-transition"), BRIDGE_ISSUER: transitionBase, DITO_ISSUER: upstreamBase, DITO_AUTHORIZATION_ENDPOINT: `${upstreamBase}/authorize`, FORGEJO_CLIENT_CONFIG: join(temporary, "forgejo.json"), RP_DID_KEY_FILE: rpKeyFile },
    stdout: "ignore", stderr: "ignore",
  });
  async function transitionReady() { for (let i = 0; i < 100; i++) { try { if ((await fetch(`${transitionBase}/healthz`)).ok) return; } catch {} await Bun.sleep(20); } throw new Error("transition bridge did not start"); }
  afterAll(async () => { transitionBridge.kill(); await transitionBridge.exited; });

  test("PLAN8 regression: RP_DID_KEY_FILE alone (no RP_RESPONSE_URI) keeps using JAR + code, not direct_post", async () => {
    await transitionReady();
    const authorize = new URL(`${transitionBase}/authorize`); authorize.search = new URLSearchParams({ response_type: "code", client_id: "forgejo", redirect_uri: forgejoRedirect, scope: "openid profile", state: "transition-state", code_challenge: "D".repeat(43), code_challenge_method: "S256" }).toString();
    const first = await fetch(authorize, { redirect: "manual" });
    const ditoUrl = new URL(first.headers.get("location")!);
    expect(ditoUrl.searchParams.get("client_id")).toBe(rpDid);
    expect(ditoUrl.searchParams.get("response_type")).toBe("code");
    const payload = base64urlJson(ditoUrl.searchParams.get("request")!.split(".")[1]!);
    expect(payload).toMatchObject({ iss: rpDid, client_id: rpDid, client_id_scheme: "did", response_type: "code", redirect_uri: `${transitionBase}/callback` });
    expect(payload.response_mode).toBeUndefined();
    expect(payload.response_uri).toBeUndefined();
    expect(typeof payload.code_challenge).toBe("string");
    // Completes end to end exactly as PLAN6 left it, through /callback --
    // the mock upstream's id_token audience must match this RP DID, not
    // the shared instance's DCR client_id.
    requestedAudience = rpDid;
    try {
      const callback = await fetch(`${transitionBase}/callback?code=dito-code&state=${encodeURIComponent(payload.state)}`, { redirect: "manual" });
      const forgejoUrl = new URL(callback.headers.get("location")!);
      expect(forgejoUrl.searchParams.get("state")).toBe("transition-state");
    } finally { requestedAudience = upstreamClientId; }
  });
}

// PLAN10: did.md's own oauth-server.ts
// (api.did.md's DCR/code+token layer -- biset's device-refresh, any future
// DCR client) now runs merged into this same process, not did-md-server's.
// These tests exercise it reached THROUGH the shared bridge instance
// spawned at the top of this file, proving both route sets coexist without
// collision -- most directly the one ambiguous path
// (/.well-known/openid-configuration), disambiguated by Host.
test("PLAN10: /.well-known/openid-configuration serves oauth-server.ts's own discovery document when Host is api.did.md", async () => {
  await ready();
  const response = await fetch(`${bridgeBase}/.well-known/openid-configuration`, { headers: { host: "api.did.md" } });
  expect(response.status).toBe(200);
  const doc = await response.json();
  expect(doc).toMatchObject({ issuer: "https://api.did.md", id_token_signing_alg_values_supported: ["EdDSA"], registration_endpoint: "https://api.did.md/v1/oauth/register" });
});

test("PLAN10: /.well-known/openid-configuration serves oidc-bridge's own discovery document for any other Host", async () => {
  await ready();
  const response = await fetch(`${bridgeBase}/.well-known/openid-configuration`);
  expect(response.status).toBe(200);
  const doc = await response.json();
  expect(doc).toMatchObject({ issuer: bridgeBase, id_token_signing_alg_values_supported: ["RS256"] });
});

test("PLAN10: /.well-known/oauth-authorization-server and /v1/oauth/register are reachable through the merged process", async () => {
  await ready();
  const metadata = await fetch(`${bridgeBase}/.well-known/oauth-authorization-server`);
  expect(metadata.status).toBe(200);
  expect((await metadata.json()).issuer).toBe("https://api.did.md");

  const registration = await fetch(`${bridgeBase}/v1/oauth/register`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ application_type: "web", client_name: "PLAN10 merge test", redirect_uris: ["https://plan10.example/callback"], grant_types: ["authorization_code"], response_types: ["code"], scope: "openid profile", token_endpoint_auth_method: "none" }),
  });
  expect(registration.status).toBe(201);
  expect((await registration.json()).client_name).toBe("PLAN10 merge test");
});

// Regression (found live 2026-09-22, fixed same session): merging oauthFetch
// into this file's handle() without also carrying over did-md-server's own
// try/catch (server/server.ts's `fail()`) let a thrown Invalid from an
// oauth-server.ts route function escape as an uncaught exception -- Bun's
// generic error page instead of a proper 400 JSON body. A browser caller
// (biset's device-refresh) would see an uncatchable "Failed to fetch"
// instead of a readable error, exactly the bug server/server.ts's own `fail`
// comment already documents having fixed once, on the other process.
test("PLAN10 regression: a malformed /v1/oauth/device-refresh request gets a proper CORS'd 400, not an uncaught exception", async () => {
  await ready();
  const response = await fetch(`${bridgeBase}/v1/oauth/device-refresh`, {
    method: "POST", headers: { "content-type": "application/json", origin: "https://t.biset.md" }, body: JSON.stringify({}),
  });
  expect(response.status).toBe(400);
  expect(response.headers.get("access-control-allow-origin")).toBe("https://t.biset.md");
  const body = await response.json();
  expect(body.error).toBe("invalid_request");
  expect(typeof body.error_description).toBe("string");
});
