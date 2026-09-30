import { multihash } from "./helpers/webvh-fixtures.ts";
// Dedicated tests for PLAN1: Identity-
// layer key resolution no longer assumes a fixed "#pass-1" fragment or an
// Ed25519-only cryptosuite/alg. The existing oauth-loopback tests only ever
// exercise "#pass-1" + EdDSA, so they cannot demonstrate the generalization
// -- these tests specifically build a DID Document whose authentication
// fragment is NOT "#pass-1", and separately forge unsupported
// cryptosuite/alg values, to prove the server's behavior is now dispatched
// by what the DID Document and proof/id_token actually claim.
import { afterAll, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createIdentityMaterial, createSelfIssuedIdToken, signEntry } from "../packages/wallet/src/did-webvh.ts";
import { buildCapabilityCredential, vpToken } from "./helpers/capability-vc.ts";

const port = 18_000 + Math.floor(Math.random() * 10_000);
const base = `http://127.0.0.1:${port}`;
const dataDir = mkdtempSync(join(tmpdir(), "did-md-identity-layer-"));
const server = Bun.spawn({
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
    await Bun.sleep(20);
  }
  throw new Error("did.md test server did not start");
}

afterAll(async () => {
  server.kill();
  await server.exited;
  rmSync(dataDir, { recursive: true, force: true });
});

// buildGenesis (client/did-webvh.ts) always names its authentication method
// "#pass-1" -- dito itself is not changed by PLAN1 (see PLAN1's "non-scope").
// This local helper reproduces buildGenesis's construction with an
// arbitrary fragment name instead, so the SERVER's fragment-independence can
// actually be exercised end to end (genesis -> publish -> authorize ->
// token), the same way a hypothetical non-dito wallet would name its key.
const SCID_PLACEHOLDER = "{SCID}";
function didFor(scid: string, username: string, domain: string): string { return `did:webvh:${scid}:${username}.${domain}`; }
function replaceScid(value: object, scid: string): any { return JSON.parse(JSON.stringify(value).split(SCID_PLACEHOLDER).join(scid)); }
function versionTime(): string { return new Date().toISOString().replace(/\.\d{3}Z$/, "Z"); }

async function buildGenesisWithFragment(args: {
  username: string; domain: string; fragment: string;
  root: Awaited<ReturnType<typeof createIdentityMaterial>>["root"];
  sign: Awaited<ReturnType<typeof createIdentityMaterial>>["sign"];
  nextSpare: Awaited<ReturnType<typeof createIdentityMaterial>>["nextSpare"];
}): Promise<any> {
  const time = versionTime();
  const placeholderDid = didFor(SCID_PLACEHOLDER, args.username, args.domain);
  const parameters = {
    method: "did:webvh:1.0",
    scid: SCID_PLACEHOLDER,
    updateKeys: [args.sign.multikey],
    nextKeyHashes: [await multihash(args.nextSpare.multikey)],
    witness: {},
    watchers: [],
    portable: true,
    deactivated: false,
    ttl: 3600,
  };
  const state = {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
    id: placeholderDid,
    verificationMethod: [{
      id: args.fragment,
      type: "Multikey",
      controller: placeholderDid,
      publicKeyMultibase: args.root.multikey,
    }],
    authentication: [args.fragment],
    service: [],
  };
  const scid = await multihash({ versionId: SCID_PLACEHOLDER, versionTime: time, parameters, state });
  const real = replaceScid({ parameters, state }, scid);
  const unsigned = {
    versionId: `1-${await multihash({ versionId: scid, versionTime: time, parameters: real.parameters, state: real.state })}`,
    versionTime: time,
    parameters: real.parameters,
    state: real.state,
  };
  return signEntry(unsigned, args.sign.privateKey, args.sign.multikey, time);
}

test("an authentication fragment other than #pass-1 can still authorize (Identity layer is fragment-independent)", async () => {
  await ready();
  const redirectUri = "http://localhost:3336/callback";
  const registered = await fetch(`${base}/v1/oauth/register`, {
    method: "POST", headers: { origin: "http://localhost:3336", "content-type": "application/json" },
    body: JSON.stringify({ application_type: "web", client_name: "Fragment Test Client", redirect_uris: [redirectUri], grant_types: ["authorization_code"], response_types: ["code"], scope: "openid profile", token_endpoint_auth_method: "none" }),
  });
  expect(registered.status).toBe(201);
  const client = await registered.json();

  const identity = await createIdentityMaterial();
  const fragment = "#device-key-1";
  const genesis = await buildGenesisWithFragment({ username: "otherfrag", domain: "did.md", fragment, root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare });
  const published = await fetch(`${base}/.well-known/did.jsonl`, { method: "PUT", headers: { host: "otherfrag.did.md", "content-type": "text/jsonl" }, body: `${JSON.stringify(genesis)}\n` });
  expect(published.status).toBe(201);
  const did = genesis.state.id as string;

  const issuedAtMs = Date.now(); const issuedAt = new Date(issuedAtMs).toISOString();
  const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");

  // The credential's proof.verificationMethod names the NON-"#pass-1"
  // fragment -- proof over exactly the same DID Document that buildGenesis
  // with "#pass-1" would have used, but under a different key name.
  const vc = await buildCapabilityCredential({ privateKey: identity.root.privateKey, did, verificationMethod: `${did}${fragment}`, capabilityType: "did.md/DeviceCapability", audience: client.client_id, scope: ["openid", "profile"], issuedAt, expiresAt: new Date(issuedAtMs + 3600_000).toISOString() });
  const idToken = await createIdTokenWithKid({ iss: did, sub: did, aud: client.client_id, iat: Math.floor(issuedAtMs / 1000), exp: Math.floor(issuedAtMs / 1000) + 3600 }, identity.root.privateKey, `${did}${fragment}`);

  const completed = await fetch(`${base}/v1/oauth/authorize/complete`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_id: client.client_id, redirect_uri: redirectUri, state: "fragment-state-value", code_challenge: challenge, code_challenge_method: "S256", vp_token: vpToken(vc), id_token: idToken }) });
  if (!completed.ok) throw new Error(await completed.text());
  const code = (await completed.json()).code;

  const exchanged = await fetch(`${base}/v1/oauth/token`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_id: client.client_id, code, redirect_uri: redirectUri, code_verifier: verifier, grant_type: "authorization_code" }) });
  expect(exchanged.status).toBe(200);
  const tokens = await exchanged.json();
  const header = JSON.parse(Buffer.from(tokens.id_token.split(".")[0], "base64url").toString());
  // The server accepted and passed through a kid that is NOT "#pass-1" --
  // proof the fragment name is resolved from the DID Document, not assumed.
  expect(header.kid).toBe(`${did}${fragment}`);
  const claims = JSON.parse(Buffer.from(tokens.id_token.split(".")[1], "base64url").toString());
  expect(claims).toMatchObject({ iss: did, sub: did, aud: client.client_id });
});

test("a proof with an unsupported cryptosuite is rejected explicitly, not silently accepted", async () => {
  await ready();
  const redirectUri = "http://localhost:3337/callback";
  const registered = await fetch(`${base}/v1/oauth/register`, {
    method: "POST", headers: { origin: "http://localhost:3337", "content-type": "application/json" },
    body: JSON.stringify({ application_type: "web", client_name: "Bad Cryptosuite Client", redirect_uris: [redirectUri], grant_types: ["authorization_code"], response_types: ["code"], scope: "openid", token_endpoint_auth_method: "none" }),
  });
  const client = await registered.json();

  const identity = await createIdentityMaterial();
  const { buildGenesis } = await import("../packages/wallet/src/did-webvh.ts");
  const genesis = await buildGenesis({ username: "badsuite", root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare, api: base, domain: "did.md" });
  await fetch(`${base}/.well-known/did.jsonl`, { method: "PUT", headers: { host: "badsuite.did.md", "content-type": "text/jsonl" }, body: `${JSON.stringify(genesis)}\n` });
  const did = genesis.state.id as string;

  const issuedAtMs = Date.now(); const issuedAt = new Date(issuedAtMs).toISOString();
  const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");

  const vc = await buildCapabilityCredential({ privateKey: identity.root.privateKey, did, verificationMethod: `${did}#pass-1`, capabilityType: "did.md/DeviceCapability", audience: client.client_id, scope: ["openid"], issuedAt, expiresAt: new Date(issuedAtMs + 3600_000).toISOString() });
  // Forge an unsupported cryptosuite on the embedded proof after signing
  // (the signature no longer matches, but that must not be the reason this
  // is rejected -- the cryptosuite dispatch itself must reject it first and
  // explicitly).
  const forgedVc = { ...vc, proof: { ...vc.proof, cryptosuite: "ecdsa-jcs-2019" } };
  const idToken = createSelfIssuedIdToken({ iss: did, sub: did, aud: client.client_id, iat: Math.floor(issuedAtMs / 1000), exp: Math.floor(issuedAtMs / 1000) + 3600 }, { privateKey: identity.root.privateKey, did });

  const completed = await fetch(`${base}/v1/oauth/authorize/complete`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_id: client.client_id, redirect_uri: redirectUri, state: "bad-cryptosuite-state", code_challenge: challenge, code_challenge_method: "S256", vp_token: vpToken(forgedVc), id_token: idToken }) });
  expect(completed.status).toBe(400);
  expect(await completed.text()).toContain("Wallet proof");
});

test("an id_token with an unsupported alg is rejected explicitly, not silently accepted", async () => {
  await ready();
  const redirectUri = "http://localhost:3338/callback";
  const registered = await fetch(`${base}/v1/oauth/register`, {
    method: "POST", headers: { origin: "http://localhost:3338", "content-type": "application/json" },
    body: JSON.stringify({ application_type: "web", client_name: "Bad Alg Client", redirect_uris: [redirectUri], grant_types: ["authorization_code"], response_types: ["code"], scope: "openid", token_endpoint_auth_method: "none" }),
  });
  const client = await registered.json();

  const identity = await createIdentityMaterial();
  const { buildGenesis } = await import("../packages/wallet/src/did-webvh.ts");
  const genesis = await buildGenesis({ username: "badalg", root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare, api: base, domain: "did.md" });
  await fetch(`${base}/.well-known/did.jsonl`, { method: "PUT", headers: { host: "badalg.did.md", "content-type": "text/jsonl" }, body: `${JSON.stringify(genesis)}\n` });
  const did = genesis.state.id as string;

  const issuedAtMs = Date.now(); const issuedAt = new Date(issuedAtMs).toISOString();
  const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");

  const vc = await buildCapabilityCredential({ privateKey: identity.root.privateKey, did, verificationMethod: `${did}#pass-1`, capabilityType: "did.md/DeviceCapability", audience: client.client_id, scope: ["openid"], issuedAt, expiresAt: new Date(issuedAtMs + 3600_000).toISOString() });
  const idToken = createSelfIssuedIdToken({ iss: did, sub: did, aud: client.client_id, iat: Math.floor(issuedAtMs / 1000), exp: Math.floor(issuedAtMs / 1000) + 3600 }, { privateKey: identity.root.privateKey, did });
  // Forge the header's alg after signing (kid/typ/signature length still
  // look valid -- only the alg is wrong). The header b64url changes, so the
  // original signature would fail anyway, but the alg dispatch must reject
  // this BEFORE ever reaching signature verification.
  const [headerPart, payloadPart, signaturePart] = idToken.split(".");
  const forgedHeader = { ...JSON.parse(Buffer.from(headerPart, "base64url").toString()), alg: "RS256" };
  const forgedIdToken = `${Buffer.from(JSON.stringify(forgedHeader)).toString("base64url")}.${payloadPart}.${signaturePart}`;

  const completed = await fetch(`${base}/v1/oauth/authorize/complete`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_id: client.client_id, redirect_uri: redirectUri, state: "bad-alg-state-value", code_challenge: challenge, code_challenge_method: "S256", vp_token: vpToken(vc), id_token: forgedIdToken }) });
  expect(completed.status).toBe(400);
  expect(await completed.text()).toContain("id_token");
});

// createSelfIssuedIdToken (client/did-webvh.ts) always signs with the DID's
// Root key under a hardcoded "#pass-1" kid. This local helper is the same
// construction with an arbitrary kid, mirroring buildGenesisWithFragment
// above -- needed only for the fragment-independence test.
async function createIdTokenWithKid(claims: Record<string, unknown>, privateKey: Uint8Array, kid: string): Promise<string> {
  const { ed25519 } = await import("@noble/curves/ed25519.js");
  const header = { alg: "EdDSA", typ: "JWT", kid };
  const encoder = new TextEncoder();
  const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
  const headerPart = b64url(encoder.encode(JSON.stringify(header)));
  const payloadPart = b64url(encoder.encode(JSON.stringify(claims)));
  const signature = ed25519.sign(encoder.encode(`${headerPart}.${payloadPart}`), privateKey);
  return `${headerPart}.${payloadPart}.${b64url(signature)}`;
}
