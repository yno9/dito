import { afterAll, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildGenesis, createDataIntegrityProof, createIdentityMaterial, createSelfIssuedIdToken, preparePortableImport } from "../packages/wallet/src/did-webvh.ts";
import { buildCapabilityCredential, vpToken } from "./helpers/capability-vc.ts";

const port = 18_000 + Math.floor(Math.random() * 10_000);
const base = `http://127.0.0.1:${port}`;
const dataDir = mkdtempSync(join(tmpdir(), "did-md-oauth-loopback-"));
const server = Bun.spawn({
  cmd: [process.execPath, "server/server.ts"],
  cwd: new URL("..", import.meta.url).pathname,
  env: { ...process.env, PORT: String(port), DATA_DIR: dataDir, OAUTH_DID_RP_DOMAINS: "t.biset.md,t.example.invalid", IDENTITY_FETCH_BASE_URL: base },
  stdout: "ignore",
  stderr: "ignore",
});

async function ready(): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      if ((await fetch(`${base}/healthz`)).ok) return;
    } catch { /* server is still starting */ }
    await Bun.sleep(20);
  }
  throw new Error("did.md test server did not start");
}

afterAll(async () => {
  server.kill();
  await server.exited;
  rmSync(dataDir, { recursive: true, force: true });
});

test("OAuth allows loopback and local file clients, but not arbitrary HTTP", async () => {
  await ready();
  const origin = "http://localhost:3000";
  const metadata = await fetch(`${base}/.well-known/oauth-authorization-server`, { headers: { origin } });
  expect(metadata.headers.get("access-control-allow-origin")).toBe(origin);

  const registration = await fetch(`${base}/v1/oauth/register`, {
    method: "POST",
    headers: { origin, "content-type": "application/json" },
    body: JSON.stringify({
      application_type: "web",
      client_name: "Local OAuth Client",
      redirect_uris: ["http://localhost:3000/wallet/callback"],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      scope: "identity:read key:authorize",
      token_endpoint_auth_method: "none",
    }),
  });
  expect(registration.status).toBe(201);
  expect((await registration.json()).redirect_uris).toEqual(["http://localhost:3000/wallet/callback"]);

  const fileMetadata = await fetch(`${base}/.well-known/oauth-authorization-server`, { headers: { origin: "null" } });
  expect(fileMetadata.headers.get("access-control-allow-origin")).toBe("null");
  const fileRegistration = await fetch(`${base}/v1/oauth/register`, {
    method: "POST",
    headers: { origin: "null", "content-type": "application/json" },
    body: JSON.stringify({
      application_type: "web",
      client_name: "Packaged OAuth Client",
      redirect_uris: ["file:///opt/client/index.html"],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      scope: "identity:read key:authorize",
      token_endpoint_auth_method: "none",
    }),
  });
  expect(fileRegistration.status).toBe(201);
  expect((await fileRegistration.json()).redirect_uris).toEqual(["file:///opt/client/index.html"]);

  const untrusted = await fetch(`${base}/.well-known/oauth-authorization-server`, { headers: { origin: "http://example.test" } });
  expect(untrusted.headers.get("access-control-allow-origin")).toBeNull();
});

// Regression (found live, 2026-09-21, t.biset.md): an OAuth endpoint's
// ERROR response used the restrictive DID-document cors() instead of the
// permissive oauthCors() -- a real biset user's stale device-refresh got a
// same 400 Bad Request the server always intended, but the browser reported
// it as an opaque CORS failure instead, and biset's own catch handling
// (which reads the response body) never even ran, so it could not recover.
test("an OAuth endpoint's error response still carries access-control-allow-origin for the caller's origin", async () => {
  await ready();
  const origin = "https://t.biset.md";
  const response = await fetch(`${base}/v1/oauth/device-refresh`, {
    method: "POST", headers: { origin, "content-type": "application/json" },
    body: JSON.stringify({ client_id: "client_notregistered00000000000000000000", vp_token: { capability: [{}] } }),
  });
  expect(response.status).toBe(400);
  expect(response.headers.get("access-control-allow-origin")).toBe(origin);
});

test("discovery publishes one unified endpoint set, no jwks_uri", async () => {
  await ready();
  const oauthMetadata = await (await fetch(`${base}/.well-known/oauth-authorization-server`)).json();
  const oidcMetadata = await (await fetch(`${base}/.well-known/openid-configuration`)).json();
  // Both well-known paths serve the same document -- one protocol.
  expect(oauthMetadata).toEqual(oidcMetadata);
  expect(oauthMetadata.issuer).toBe("https://api.did.md");
  expect(oauthMetadata.authorization_endpoint).toBe("https://app.did.md/authorize");
  expect(oauthMetadata.token_endpoint).toBe("https://api.did.md/v1/oauth/token");
  expect(oauthMetadata.id_token_signing_alg_values_supported).toEqual(["EdDSA"]);
  // No jwks_uri: an id_token is signed by the Wallet's own DID key, not any
  // key this server holds, so there is no server-side key set to publish.
  expect(oauthMetadata.jwks_uri).toBeUndefined();
  expect(oauthMetadata.token_endpoint_auth_methods_supported).toEqual(["none"]);
});

test("a conventional (non-DPoP) client gets a Wallet self-issued id_token, never server-signed", async () => {
  await ready();
  const redirectUri = "http://localhost:3334/callback";
  const registered = await fetch(`${base}/v1/oauth/register`, {
    method: "POST", headers: { origin: "http://localhost:3334", "content-type": "application/json" },
    body: JSON.stringify({ application_type: "web", client_name: "Self-Issued Client", redirect_uris: [redirectUri], grant_types: ["authorization_code"], response_types: ["code"], scope: "openid profile", token_endpoint_auth_method: "none" }),
  });
  expect(registered.status).toBe(201);
  const client = await registered.json();

  const identity = await createIdentityMaterial();
  const genesis = await buildGenesis({ username: "selfissued", root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare, api: base, domain: "did.md" });
  expect((await fetch(`${base}/.well-known/did.jsonl`, { method: "PUT", headers: { host: "selfissued.did.md", "content-type": "text/jsonl" }, body: `${JSON.stringify(genesis)}\n` })).status).toBe(201);
  const did = genesis.state.id as string;
  const issuedAtMs = Date.now(); const issuedAt = new Date(issuedAtMs).toISOString();
  const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");

  // No deviceJkt: this is exactly the shape a conventional relying party's
  // capability document takes -- one unified document type for every client.
  const vc = await buildCapabilityCredential({ privateKey: identity.root.privateKey, did, verificationMethod: `${did}#pass-1`, capabilityType: "did.md/DeviceCapability", audience: client.client_id, scope: ["openid", "profile"], issuedAt, expiresAt: new Date(issuedAtMs + 3600_000).toISOString() });
  const idToken = createSelfIssuedIdToken({ iss: did, sub: did, aud: client.client_id, iat: Math.floor(issuedAtMs / 1000), exp: Math.floor(issuedAtMs / 1000) + 3600, preferred_username: "selfissued", nickname: "selfissued", name: "selfissued" }, { privateKey: identity.root.privateKey, did });

  const completed = await fetch(`${base}/v1/oauth/authorize/complete`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_id: client.client_id, redirect_uri: redirectUri, state: "self-issued-state-value", code_challenge: challenge, code_challenge_method: "S256", vp_token: vpToken(vc), id_token: idToken }) });
  if (!completed.ok) throw new Error(await completed.text());
  const code = (await completed.json()).code;

  // No DPoP header: a non-DPoP capability's token exchange takes none.
  const exchanged = await fetch(`${base}/v1/oauth/token`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_id: client.client_id, code, redirect_uri: redirectUri, code_verifier: verifier, grant_type: "authorization_code" }) });
  expect(exchanged.status).toBe(200);
  const tokens = await exchanged.json();
  expect(tokens.token_type).toBe("Bearer");
  // Passed through verbatim -- the server never touches, re-signs, or
  // re-derives it.
  expect(tokens.id_token).toBe(idToken);

  const [headerPart, payloadPart, signaturePart] = tokens.id_token.split(".");
  const header = JSON.parse(Buffer.from(headerPart, "base64url").toString());
  expect(header).toMatchObject({ alg: "EdDSA", typ: "JWT", kid: `${did}#pass-1` });
  const payload = JSON.parse(Buffer.from(payloadPart, "base64url").toString());
  expect(payload).toMatchObject({ iss: did, sub: did, aud: client.client_id, preferred_username: "selfissued" });
  // Independently verify the signature against the identity's OWN public
  // key (derived client-side, never sent to the server) -- proving the
  // server could not have produced this signature itself.
  const publicKeyBytes = (await import("@noble/curves/ed25519.js")).ed25519.getPublicKey(identity.root.privateKey);
  const imported = await crypto.subtle.importKey("raw", publicKeyBytes, { name: "Ed25519" }, false, ["verify"]);
  const valid = await crypto.subtle.verify({ name: "Ed25519" }, imported, Buffer.from(signaturePart, "base64url"), new TextEncoder().encode(`${headerPart}.${payloadPart}`));
  expect(valid).toBe(true);
});

// Regression (found live, 2026-09-21, via oidc-bridge -> Forgejo): a
// standard-conforming OAuth client sends the token endpoint
// application/x-www-form-urlencoded, per RFC 6749 §4.1.3 -- oidc-bridge's
// DitoClient.exchange() does exactly this. The server had been changed to
// parse the token endpoint body as JSON only, so a form-encoded request hit
// an uncaught JSON.parse SyntaxError and surfaced to the RP as a bare 500,
// not the intended PKCE/grant_type validation. dito/biset both send JSON
// (their own choice, still supported) -- this proves form-encoding works
// too, independent of that other path.
test("the token endpoint also accepts a standard application/x-www-form-urlencoded request (oidc-bridge's own wire format)", async () => {
  await ready();
  const redirectUri = "http://localhost:3343/callback";
  const registered = await fetch(`${base}/v1/oauth/register`, {
    method: "POST", headers: { origin: "http://localhost:3343", "content-type": "application/json" },
    body: JSON.stringify({ application_type: "web", client_name: "Form-Encoded Client", redirect_uris: [redirectUri], grant_types: ["authorization_code"], response_types: ["code"], scope: "openid", token_endpoint_auth_method: "none" }),
  });
  const client = await registered.json();

  const identity = await createIdentityMaterial();
  const genesis = await buildGenesis({ username: "formencoded", root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare, api: base, domain: "did.md" });
  await fetch(`${base}/.well-known/did.jsonl`, { method: "PUT", headers: { host: "formencoded.did.md", "content-type": "text/jsonl" }, body: `${JSON.stringify(genesis)}\n` });
  const did = genesis.state.id as string;
  const issuedAtMs = Date.now(); const issuedAt = new Date(issuedAtMs).toISOString();
  const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");

  const vc = await buildCapabilityCredential({ privateKey: identity.root.privateKey, did, verificationMethod: `${did}#pass-1`, capabilityType: "did.md/DeviceCapability", audience: client.client_id, scope: ["openid"], issuedAt, expiresAt: new Date(issuedAtMs + 3600_000).toISOString() });
  const idToken = createSelfIssuedIdToken({ iss: did, sub: did, aud: client.client_id, iat: Math.floor(issuedAtMs / 1000), exp: Math.floor(issuedAtMs / 1000) + 3600 }, { privateKey: identity.root.privateKey, did });
  const completed = await fetch(`${base}/v1/oauth/authorize/complete`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_id: client.client_id, redirect_uri: redirectUri, state: "form-encoded-state-value", code_challenge: challenge, code_challenge_method: "S256", vp_token: vpToken(vc), id_token: idToken }) });
  if (!completed.ok) throw new Error(await completed.text());
  const code = (await completed.json()).code;

  // The exact wire format oidc-bridge's DitoClient.exchange() sends.
  const formBody = new URLSearchParams({ grant_type: "authorization_code", client_id: client.client_id, redirect_uri: redirectUri, code, code_verifier: verifier });
  const exchanged = await fetch(`${base}/v1/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: formBody });
  expect(exchanged.status).toBe(200);
  const tokens = await exchanged.json();
  expect(tokens.id_token).toBe(idToken);
});

// Forgejo is now just another dynamically-registered client -- the old
// hardcoded client_id="forgejo"/client_secret confidential-client path is
// gone. Forgejo's own OIDC verifier needs a matching update (resolve `kid`
// against the DID's did.jsonl instead of a jwks_uri); this test only
// covers dito's side of that contract.
test("a Forgejo-shaped client (dynamically registered) gets a self-issued id_token", async () => {
  await ready();
  const redirectUri = "https://forgejo.example.com/user/oauth2/dito/callback";
  const registered = await fetch(`${base}/v1/oauth/register`, {
    method: "POST", headers: { origin: "https://forgejo.example.com", "content-type": "application/json" },
    body: JSON.stringify({ application_type: "web", client_name: "Forgejo", redirect_uris: [redirectUri], grant_types: ["authorization_code"], response_types: ["code"], scope: "openid profile email", token_endpoint_auth_method: "none" }),
  });
  expect(registered.status).toBe(201);
  const client = await registered.json();

  const identity = await createIdentityMaterial();
  const genesis = await buildGenesis({ username: "oidcalice", displayName: "OIDC Alice", root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare, api: base, domain: "did.md" });
  expect((await fetch(`${base}/.well-known/did.jsonl`, { method: "PUT", headers: { host: "oidcalice.did.md", "content-type": "text/jsonl" }, body: `${JSON.stringify(genesis)}\n` })).status).toBe(201);
  const did = genesis.state.id as string;
  const issuedAtMs = Date.now(); const issuedAt = new Date(issuedAtMs).toISOString();
  const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");
  const scid = did.split(":")[2]!;

  const vc = await buildCapabilityCredential({ privateKey: identity.root.privateKey, did, verificationMethod: `${did}#pass-1`, capabilityType: "did.md/DeviceCapability", audience: client.client_id, scope: ["openid", "profile", "email"], issuedAt, expiresAt: new Date(issuedAtMs + 3600_000).toISOString() });
  const idToken = createSelfIssuedIdToken({ iss: did, sub: did, aud: client.client_id, iat: Math.floor(issuedAtMs / 1000), exp: Math.floor(issuedAtMs / 1000) + 3600, preferred_username: scid, nickname: scid, name: scid, email: `${scid}@users.did.invalid`, email_verified: false }, { privateKey: identity.root.privateKey, did });

  const completed = await fetch(`${base}/v1/oauth/authorize/complete`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_id: client.client_id, redirect_uri: redirectUri, state: "test-state-value", code_challenge: challenge, code_challenge_method: "S256", vp_token: vpToken(vc), id_token: idToken }) });
  if (!completed.ok) throw new Error(await completed.text());
  const code = (await completed.json()).code;
  const exchanged = await fetch(`${base}/v1/oauth/token`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_id: client.client_id, code, redirect_uri: redirectUri, code_verifier: verifier, grant_type: "authorization_code" }) });
  expect(exchanged.status).toBe(200);
  const tokens = await exchanged.json();
  const claims = JSON.parse(Buffer.from(tokens.id_token.split(".")[1], "base64url").toString());
  expect(claims).toMatchObject({ iss: did, sub: did, aud: client.client_id, preferred_username: scid, name: scid, email: `${scid}@users.did.invalid`, email_verified: false });
  const userinfo = await fetch(`${base}/v1/oauth/userinfo`, { headers: { authorization: `Bearer ${tokens.access_token}` } });
  expect(await userinfo.json()).toMatchObject({ sub: did, preferred_username: scid });
});

test("an un-hatched genesis can still authorize, via its own supplied DID log", async () => {
  await ready();
  const identity = await createIdentityMaterial();
  const genesis = await buildGenesis({ username: "un", root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare, api: base, domain: "hatched" });
  const did = genesis.state.id as string;
  const issuedAtMs = Date.now(); const issuedAt = new Date(issuedAtMs).toISOString();
  const redirectUri = "https://forgejo.example.com/user/oauth2/dito/callback";
  const registered = await fetch(`${base}/v1/oauth/register`, {
    method: "POST", headers: { origin: "https://forgejo.example.com", "content-type": "application/json" },
    body: JSON.stringify({ application_type: "web", client_name: "Forgejo", redirect_uris: [redirectUri], grant_types: ["authorization_code"], response_types: ["code"], scope: "openid profile", token_endpoint_auth_method: "none" }),
  });
  const client = await registered.json();
  const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");

  const vc = await buildCapabilityCredential({ privateKey: identity.root.privateKey, did, verificationMethod: `${did}#pass-1`, capabilityType: "did.md/DeviceCapability", audience: client.client_id, scope: ["openid", "profile"], issuedAt, expiresAt: new Date(issuedAtMs + 3600_000).toISOString() });
  const idToken = createSelfIssuedIdToken({ iss: did, sub: did, aud: client.client_id, iat: Math.floor(issuedAtMs / 1000), exp: Math.floor(issuedAtMs / 1000) + 3600, preferred_username: "un" }, { privateKey: identity.root.privateKey, did });

  const completed = await fetch(`${base}/v1/oauth/authorize/complete`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_id: client.client_id, redirect_uri: redirectUri, state: "provisional-state", code_challenge: challenge, code_challenge_method: "S256", vp_token: vpToken(vc), id_token: idToken, did_log: `${JSON.stringify(genesis)}\n` }) });
  if (!completed.ok) throw new Error(await completed.text());
  const code = (await completed.json()).code;
  const exchanged = await fetch(`${base}/v1/oauth/token`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_id: client.client_id, code, redirect_uri: redirectUri, code_verifier: verifier, grant_type: "authorization_code" }) });
  expect(exchanged.status).toBe(200);
  const claims = JSON.parse(Buffer.from((await exchanged.json()).id_token.split(".")[1], "base64url").toString());
  expect(claims).toMatchObject({ sub: did, preferred_username: "un" });
});

test("a moved identity can still authorize with its ORIGINAL genesis as did_log", async () => {
  // Regression: suppliedAuthorityFromDidLog used to derive the authority
  // DID from the supplied log's OWN state.id (the genesis's original, pre-
  // move domain) instead of the capability's actual (post-move) issuer --
  // #pass-1 is recorded as a relative reference specifically so the same
  // genesis authorizes the identity under ANY of its domains, but that only
  // works if the check is by SCID, not by the genesis's own literal DID.
  await ready();
  const identity = await createIdentityMaterial();
  const genesis = await buildGenesis({ username: "premove", root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare, api: base, domain: "elsewhere.example" });
  const moved = await preparePortableImport({ entries: [genesis], username: "postmove", domain: "did.md", masterSeed: identity.masterSeed });
  const did = moved.did;
  expect(did).not.toBe(genesis.state.id);

  const redirectUri = "http://localhost:3335/callback";
  const registered = await fetch(`${base}/v1/oauth/register`, {
    method: "POST", headers: { origin: "http://localhost:3335", "content-type": "application/json" },
    body: JSON.stringify({ application_type: "web", client_name: "Moved Identity Client", redirect_uris: [redirectUri], grant_types: ["authorization_code"], response_types: ["code"], scope: "openid", token_endpoint_auth_method: "none" }),
  });
  const client = await registered.json();
  const issuedAtMs = Date.now(); const issuedAt = new Date(issuedAtMs).toISOString();
  const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");

  const vc = await buildCapabilityCredential({ privateKey: identity.root.privateKey, did, verificationMethod: `${did}#pass-1`, capabilityType: "did.md/DeviceCapability", audience: client.client_id, scope: ["openid"], issuedAt, expiresAt: new Date(issuedAtMs + 3600_000).toISOString() });
  const idToken = createSelfIssuedIdToken({ iss: did, sub: did, aud: client.client_id, iat: Math.floor(issuedAtMs / 1000), exp: Math.floor(issuedAtMs / 1000) + 3600 }, { privateKey: identity.root.privateKey, did });

  // did_log is the ORIGINAL (pre-move) genesis -- not the moved.entry.
  const completed = await fetch(`${base}/v1/oauth/authorize/complete`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_id: client.client_id, redirect_uri: redirectUri, state: "moved-state-value", code_challenge: challenge, code_challenge_method: "S256", vp_token: vpToken(vc), id_token: idToken, did_log: `${JSON.stringify(genesis)}\n` }) });
  if (!completed.ok) throw new Error(await completed.text());
  const code = (await completed.json()).code;
  const exchanged = await fetch(`${base}/v1/oauth/token`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_id: client.client_id, code, redirect_uri: redirectUri, code_verifier: verifier, grant_type: "authorization_code" }) });
  expect(exchanged.status).toBe(200);
  const claims = JSON.parse(Buffer.from((await exchanged.json()).id_token.split(".")[1], "base64url").toString());
  expect(claims).toMatchObject({ sub: did });
});

test("routing metadata is published as an origin-root did:webvh resource", async () => {
  await ready();
  const identity = await createIdentityMaterial();
  const entry = await buildGenesis({
    username: "alice", displayName: "", root: identity.root, sign: identity.sign,
    nextSpare: identity.nextSpare, api: base, domain: "did.md",
  });
  const identityHeaders = { host: "alice.did.md" };
  const log = await fetch(`${base}/.well-known/did.jsonl`, {
    method: "PUT", headers: { ...identityHeaders, "content-type": "text/jsonl" },
    body: `${JSON.stringify(entry)}\n`,
  });
  expect(log.status).toBe(201);

  const document = { service: [{ id: "#mediator", type: "DIDCommMessaging", serviceEndpoint: "https://mediator.example" }] };
  const proof = await createDataIntegrityProof(document, {
    privateKey: identity.sign.privateKey,
    verificationMethod: `did:key:${identity.sign.multikey}#${identity.sign.multikey}`,
    proofPurpose: "assertionMethod",
  });
  const published = await fetch(`${base}/routing.json`, {
    method: "PUT", headers: { ...identityHeaders, "content-type": "application/json" },
    body: JSON.stringify({ ...document, proof }),
  });
  expect(published.status).toBe(204);

  const resolved = await fetch(`${base}/routing.json`, { headers: identityHeaders });
  expect(resolved.status).toBe(200);
  expect(await resolved.json()).toEqual(document);
  const legacy = await fetch(`${base}/.well-known/routing.json`, { headers: identityHeaders });
  expect(legacy.status).toBe(200);
  expect(await legacy.json()).toEqual(document);
});

test("a complete portable history can be imported to a new did.md location", async () => {
  await ready();
  const identity = await createIdentityMaterial();
  const genesis = await buildGenesis({
    username: "old", root: identity.root, sign: identity.sign,
    nextSpare: identity.nextSpare, api: base, domain: "example.com",
  });
  const moved = await preparePortableImport({
    entries: [genesis], username: "moved", domain: "did.md", masterSeed: identity.masterSeed,
  });
  const response = await fetch(`${base}/.well-known/did.jsonl`, {
    method: "PUT", headers: { host: "moved.did.md", "content-type": "text/jsonl" },
    body: `${JSON.stringify(genesis)}\n${JSON.stringify(moved.entry)}\n`,
  });
  expect(response.status).toBe(201);
  const log = await (await fetch(`${base}/.well-known/did.jsonl`, { headers: { host: "moved.did.md" } })).text();
  expect(log.trimEnd().split("\n")).toHaveLength(2);
  expect(JSON.parse(log.trimEnd().split("\n").at(-1)!).state.alsoKnownAs).toEqual([genesis.state.id]);
});

// PLAN6: a relying party can authenticate itself with a did:webvh client_id
// (JAR/client_id_scheme=did) instead of a DCR-issued client_XXXX id. This
// server never sees the JAR itself -- verification of the request object
// happens client-side, in dito's own frontend (client/app.ts, see
// PLAN6-rp-did-authentication.md §0.2) -- but /v1/oauth/authorize/complete
// is a public HTTP API independent of that browser flow, so it must
// independently resolve the RP's own DID document rather than trust that
// dito already did (§0.3bis). These tests only exercise input validation
// and branch selection (oauthClientId's format check, and
// oauthAuthorizeComplete choosing DID resolution over the DCR client
// registry) -- a real resolution requires a live HTTPS host for the RP's
// domain, which packages/did-verify's and client/did-webvh.ts's own test
// suites already cover with a mocked fetch.
test("authorize/complete with a did:webvh client_id resolves the RP's own DID document instead of the DCR registry", async () => {
  await ready();
  // t.example.invalid cannot resolve -- the point is only to prove the
  // server *attempted* did:webvh resolution (a network/DNS-shaped failure)
  // rather than falling through to "authorization redirect URI is not
  // registered", which is what the old DCR-only code path would have said
  // for an unregistered client_id.
  const clientId = "did:webvh:QmNf4Y7DyYWTZcrMdQMwftYe5JmcKXfPrxpqwriHa3A7w5:t.example.invalid";
  const completed = await fetch(`${base}/v1/oauth/authorize/complete`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_id: clientId, redirect_uri: "https://t.example.invalid/callback", state: "did-client-state-value", code_challenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ", code_challenge_method: "S256", vp_token: { capability: [{}] } }),
  });
  expect(completed.status).toBe(500);
  const text = await completed.text();
  expect(text).not.toContain("authorization redirect URI is not registered");
});

test("a did:webvh client_id with a malformed domain is rejected by input validation before any resolution attempt", async () => {
  await ready();
  const clientId = "did:webvh:z6MkfakeRpScidForTestingOnlyXXXXXXXXXXXX:not a domain";
  const completed = await fetch(`${base}/v1/oauth/authorize/complete`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_id: clientId, redirect_uri: "https://example.test/callback", state: "did-client-state-value", code_challenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ", code_challenge_method: "S256", vp_token: { capability: [{}] } }),
  });
  expect(completed.status).toBe(400);
  expect(await completed.text()).toContain("client_id is invalid");
});

// Security review (2026-09-21): an unauthenticated caller of this public
// endpoint could otherwise pick any did:webvh domain and make this server
// fetch it (SSRF into internal infrastructure, cloud metadata endpoints,
// etc.). OAUTH_DID_RP_DOMAINS (set to "t.biset.md,t.example.invalid" for
// this test server, see the top of this file) must reject a domain outside
// that allowlist *before* attempting any resolution -- confirmed here by a
// domain that would otherwise behave exactly like the allowed one above.
test("a did:webvh client_id outside OAUTH_DID_RP_DOMAINS is rejected before any resolution is attempted (SSRF guard)", async () => {
  await ready();
  const clientId = "did:webvh:z6MkfakeRpScidForTestingOnlyXXXXXXXXXXXX:internal.example.invalid";
  const completed = await fetch(`${base}/v1/oauth/authorize/complete`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_id: clientId, redirect_uri: "https://internal.example.invalid/callback", state: "did-client-state-value", code_challenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ", code_challenge_method: "S256", vp_token: { capability: [{}] } }),
  });
  expect(completed.status).toBe(400);
  expect(await completed.text()).toContain("not an accepted relying party domain");
});

test("a did:webvh client_id is rejected outright when OAUTH_DID_RP_DOMAINS is unset (fail closed by default)", async () => {
  const dedicatedPort = 18_000 + Math.floor(Math.random() * 10_000);
  const dedicatedBase = `http://127.0.0.1:${dedicatedPort}`;
  const dedicatedDataDir = mkdtempSync(join(tmpdir(), "did-md-oauth-loopback-unconfigured-"));
  const dedicated = Bun.spawn({
    cmd: [process.execPath, "server/server.ts"],
    cwd: new URL("..", import.meta.url).pathname,
    env: { ...process.env, PORT: String(dedicatedPort), DATA_DIR: dedicatedDataDir, OAUTH_DID_RP_DOMAINS: "", IDENTITY_FETCH_BASE_URL: dedicatedBase },
    stdout: "ignore", stderr: "ignore",
  });
  try {
    for (let attempt = 0; attempt < 100; attempt += 1) {
      try { if ((await fetch(`${dedicatedBase}/healthz`)).ok) break; } catch { /* still starting */ }
      await Bun.sleep(20);
    }
    const clientId = "did:webvh:z6MkfakeRpScidForTestingOnlyXXXXXXXXXXXX:t.biset.md";
    const completed = await fetch(`${dedicatedBase}/v1/oauth/authorize/complete`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ client_id: clientId, redirect_uri: "https://t.biset.md/callback", state: "did-client-state-value", code_challenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ", code_challenge_method: "S256", vp_token: { capability: [{}] } }),
    });
    expect(completed.status).toBe(400);
    expect(await completed.text()).toContain("not an accepted relying party domain");
  } finally {
    dedicated.kill(); await dedicated.exited; rmSync(dedicatedDataDir, { recursive: true, force: true });
  }
});
