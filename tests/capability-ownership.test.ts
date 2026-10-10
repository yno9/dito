// Dedicated tests for PLAN2: the
// capability document's type name is owned by the relying party, not by
// did.md. The existing oauth-loopback tests only ever use
// "did.md/DeviceCapability" (the historical default), so they cannot
// demonstrate that the server accepts an RP-chosen type name -- these tests
// specifically exercise a non-"did.md/DeviceCapability" type end to end,
// and confirm a malformed type is still rejected explicitly.
import { afterAll, expect, test } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildGenesis, createIdentityMaterial, createSelfIssuedIdToken } from "../packages/wallet/src/did-webvh.ts";
import { buildCapabilityCredential, vpToken } from "./helpers/capability-vc.ts";
import { setTimeout as sleep } from "node:timers/promises";
import { spawn } from "./spawn.ts";

const port = 18_000 + Math.floor(Math.random() * 10_000);
const base = `http://127.0.0.1:${port}`;
const dataDir = mkdtempSync(join(tmpdir(), "did-md-capability-ownership-"));
const server = spawn({
  cmd: [process.execPath, "server/server.ts"],
  cwd: new URL("..", import.meta.url).pathname,
  env: { ...process.env, PORT: String(port), DATA_DIR: dataDir, IDENTITY_FETCH_BASE_URL: base },
  stdout: "ignore",
  stderr: "ignore",
});

async function ready(): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      if ((await fetch(`${base}/healthz`)).ok) return;
    } catch { /* server is still starting */ }
    await sleep(20);
  }
  throw new Error("did.md test server did not start");
}

afterAll(async () => {
  server.kill();
  await server.exited;
  rmSync(dataDir, { recursive: true, force: true });
});

async function registerClient(name: string, redirectUri: string, scope: string) {
  const registered = await fetch(`${base}/v1/oauth/register`, {
    method: "POST", headers: { origin: new URL(redirectUri).origin, "content-type": "application/json" },
    body: JSON.stringify({ application_type: "web", client_name: name, redirect_uris: [redirectUri], grant_types: ["authorization_code"], response_types: ["code"], scope, token_endpoint_auth_method: "none" }),
  });
  expect(registered.status).toBe(201);
  return registered.json();
}

test("a relying-party-owned capability type (not did.md/DeviceCapability) is accepted", async () => {
  await ready();
  const redirectUri = "http://localhost:3339/callback";
  const client = await registerClient("biset-shaped Client", redirectUri, "openid biset:device biset:vault");

  const identity = await createIdentityMaterial();
  const genesis = await buildGenesis({ username: "rpowned", root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare, api: base, domain: "did.md" });
  await fetch(`${base}/.well-known/did.jsonl`, { method: "PUT", headers: { host: "rpowned.did.md", "content-type": "text/jsonl" }, body: `${JSON.stringify(genesis)}\n` });
  const did = genesis.state.id as string;

  const issuedAtMs = Date.now(); const issuedAt = new Date(issuedAtMs).toISOString();
  const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");

  // The RP's own type name, not did.md's -- this is the point of PLAN2.
  const vc = await buildCapabilityCredential({ privateKey: identity.root.privateKey, did, verificationMethod: `${did}#pass-1`, capabilityType: "biset.md/MessengerCapability", audience: client.client_id, scope: ["openid", "biset:device", "biset:vault"], issuedAt, expiresAt: new Date(issuedAtMs + 3600_000).toISOString() });
  const idToken = createSelfIssuedIdToken({ iss: did, sub: did, aud: client.client_id, iat: Math.floor(issuedAtMs / 1000), exp: Math.floor(issuedAtMs / 1000) + 3600 }, { privateKey: identity.root.privateKey, did });

  const completed = await fetch(`${base}/v1/oauth/authorize/complete`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_id: client.client_id, redirect_uri: redirectUri, state: "rp-owned-type-state", code_challenge: challenge, code_challenge_method: "S256", vp_token: vpToken(vc), id_token: idToken }) });
  if (!completed.ok) throw new Error(await completed.text());
  const code = (await completed.json()).code;

  const exchanged = await fetch(`${base}/v1/oauth/token`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_id: client.client_id, code, redirect_uri: redirectUri, code_verifier: verifier, grant_type: "authorization_code" }) });
  expect(exchanged.status).toBe(200);
  const tokens = await exchanged.json();
  // The server hands back the RP's own type verbatim -- it never rewrites
  // or normalizes it, proving it doesn't attach special meaning to it.
  expect(tokens.vp_token.type).toEqual(["VerifiableCredential", "biset.md/MessengerCapability"]);
  expect(tokens.vp_token.credentialSubject.scope).toEqual(["openid", "biset:device", "biset:vault"]);
});

test("two different relying parties can use two different capability type names in the same server", async () => {
  await ready();
  const redirectUriA = "http://localhost:3340/callback";
  const redirectUriB = "http://localhost:3341/callback";
  const clientA = await registerClient("Type A Client", redirectUriA, "openid");
  const clientB = await registerClient("Type B Client", redirectUriB, "openid");

  const identity = await createIdentityMaterial();
  const genesis = await buildGenesis({ username: "twotypes", root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare, api: base, domain: "did.md" });
  await fetch(`${base}/.well-known/did.jsonl`, { method: "PUT", headers: { host: "twotypes.did.md", "content-type": "text/jsonl" }, body: `${JSON.stringify(genesis)}\n` });
  const did = genesis.state.id as string;
  const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");

  for (const [client, redirectUri, typeName] of [[clientA, redirectUriA, "acme.example/WidgetCapability"], [clientB, redirectUriB, "did.md/DeviceCapability"]] as const) {
    const issuedAtMs = Date.now(); const issuedAt = new Date(issuedAtMs).toISOString();
    const vc = await buildCapabilityCredential({ privateKey: identity.root.privateKey, did, verificationMethod: `${did}#pass-1`, capabilityType: typeName, audience: client.client_id, scope: ["openid"], issuedAt, expiresAt: new Date(issuedAtMs + 3600_000).toISOString() });
    const idToken = createSelfIssuedIdToken({ iss: did, sub: did, aud: client.client_id, iat: Math.floor(issuedAtMs / 1000), exp: Math.floor(issuedAtMs / 1000) + 3600 }, { privateKey: identity.root.privateKey, did });
    const completed = await fetch(`${base}/v1/oauth/authorize/complete`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_id: client.client_id, redirect_uri: redirectUri, state: `two-types-state-${typeName.length}`, code_challenge: challenge, code_challenge_method: "S256", vp_token: vpToken(vc), id_token: idToken }) });
    if (!completed.ok) throw new Error(await completed.text());
    const code = (await completed.json()).code;
    const exchanged = await fetch(`${base}/v1/oauth/token`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_id: client.client_id, code, redirect_uri: redirectUri, code_verifier: verifier, grant_type: "authorization_code" }) });
    expect(exchanged.status).toBe(200);
    expect((await exchanged.json()).vp_token.type).toEqual(["VerifiableCredential", typeName]);
  }
});

test("a malformed capability type is rejected explicitly", async () => {
  await ready();
  const redirectUri = "http://localhost:3342/callback";
  const client = await registerClient("Malformed Type Client", redirectUri, "openid");

  const identity = await createIdentityMaterial();
  const genesis = await buildGenesis({ username: "badtype", root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare, api: base, domain: "did.md" });
  await fetch(`${base}/.well-known/did.jsonl`, { method: "PUT", headers: { host: "badtype.did.md", "content-type": "text/jsonl" }, body: `${JSON.stringify(genesis)}\n` });
  const did = genesis.state.id as string;

  const issuedAtMs = Date.now(); const issuedAt = new Date(issuedAtMs).toISOString();
  const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");

  // Not a namespaced string at all -- must still be rejected, not silently
  // accepted just because did.md no longer enforces one specific name.
  const vc = await buildCapabilityCredential({ privateKey: identity.root.privateKey, did, verificationMethod: `${did}#pass-1`, capabilityType: "   ", audience: client.client_id, scope: ["openid"], issuedAt, expiresAt: new Date(issuedAtMs + 3600_000).toISOString() });
  const idToken = createSelfIssuedIdToken({ iss: did, sub: did, aud: client.client_id, iat: Math.floor(issuedAtMs / 1000), exp: Math.floor(issuedAtMs / 1000) + 3600 }, { privateKey: identity.root.privateKey, did });

  const completed = await fetch(`${base}/v1/oauth/authorize/complete`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_id: client.client_id, redirect_uri: redirectUri, state: "bad-type-state-value", code_challenge: challenge, code_challenge_method: "S256", vp_token: vpToken(vc), id_token: idToken }) });
  expect(completed.status).toBe(400);
  expect(await completed.text()).toContain("device capability type");
});
