import { afterAll, expect, test } from "bun:test";
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildGenesis, createIdentityMaterial } from "../packages/wallet/src/did-webvh.ts";
import { buildCapabilityCredential, vpToken } from "./helpers/capability-vc.ts";

const port = 18_000 + Math.floor(Math.random() * 10_000);
const base = `http://127.0.0.1:${port}`;
const dataDir = mkdtempSync(join(tmpdir(), "did-md-oauth-outcome-"));
let server: ReturnType<typeof Bun.spawn> | undefined;

async function start() {
  await stop();
  server = Bun.spawn({ cmd: [process.execPath, "server/server.ts"], cwd: new URL("..", import.meta.url).pathname, env: { ...process.env, PORT: String(port), DATA_DIR: dataDir, IDENTITY_FETCH_BASE_URL: base }, stdout: "ignore", stderr: "ignore" });
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try { if ((await fetch(`${base}/healthz`)).ok) return; } catch { /* still starting */ }
    await Bun.sleep(20);
  }
  throw new Error("did.md test server did not start");
}
async function stop() { server?.kill(); await server?.exited; server = undefined; }
afterAll(async () => { await stop(); rmSync(dataDir, { recursive: true, force: true }); });

const registration = (extra: Record<string, unknown> = {}) => ({ application_type: "web", client_name: "Outcome Client", redirect_uris: ["http://localhost:3335/callback"], grant_types: ["authorization_code"], response_types: ["code"], scope: "identity:read", token_endpoint_auth_method: "none", ...extra });
const json = (body: unknown) => ({ method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

let identity: Awaited<ReturnType<typeof createIdentityMaterial>>; let did = ""; let counter = 0;
/** Registers a client, approves, exchanges the code; returns the Bearer token and the approval's capability id. */
async function issue(clientExtra: Record<string, unknown> = {}) {
  const registered = await fetch(`${base}/v1/oauth/register`, json(registration(clientExtra)));
  expect(registered.status).toBe(201);
  const client = await registered.json();
  if (!did) {
    identity = await createIdentityMaterial();
    const genesis = await buildGenesis({ username: "outcome", root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare, api: base, domain: "did.md" });
    expect((await fetch(`${base}/.well-known/did.jsonl`, { method: "PUT", headers: { host: "outcome.did.md", "content-type": "text/jsonl" }, body: `${JSON.stringify(genesis)}\n` })).status).toBe(201);
    did = genesis.state.id as string;
  }
  const issuedAtMs = Date.now();
  const verifier = `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ${counter++}`;
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");
  const vc = await buildCapabilityCredential({ privateKey: identity.root.privateKey, did, verificationMethod: `${did}#pass-1`, capabilityType: "did.md/DeviceCapability", audience: client.client_id, scope: ["identity:read"], issuedAt: new Date(issuedAtMs).toISOString(), expiresAt: new Date(issuedAtMs + 3600_000).toISOString() });
  const completed = await fetch(`${base}/v1/oauth/authorize/complete`, json({ client_id: client.client_id, redirect_uri: "http://localhost:3335/callback", state: "outcome-state-value-xx", code_challenge: challenge, code_challenge_method: "S256", vp_token: vpToken(vc) }));
  if (!completed.ok) throw new Error(await completed.text());
  const exchanged = await fetch(`${base}/v1/oauth/token`, json({ client_id: client.client_id, code: (await completed.json()).code, redirect_uri: "http://localhost:3335/callback", code_verifier: verifier, grant_type: "authorization_code" }));
  expect(exchanged.status).toBe(200);
  return { client, accessToken: (await exchanged.json()).access_token as string, capabilityId: (vc as { id: string }).id };
}
const report = (token: string | undefined, body: unknown) => fetch(`${base}/v1/oauth/outcome`, { method: "POST", headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: typeof body === "string" ? body : JSON.stringify(body) });
const read = (capabilityId: string, origin = "https://app.did.md") => fetch(`${base}/v1/oauth/outcome/${encodeURIComponent(capabilityId)}`, { headers: { origin } });

test("outcome_reporting round-trips through register and the public client endpoint, defaulting to false", async () => {
  await start();
  const off = await (await fetch(`${base}/v1/oauth/register`, json(registration()))).json();
  expect(off.outcome_reporting).toBe(false);
  expect((await (await fetch(`${base}/v1/oauth/clients/${off.client_id}`)).json()).outcome_reporting).toBe(false);
  const on = await (await fetch(`${base}/v1/oauth/register`, json(registration({ outcome_reporting: true })))).json();
  expect(on.outcome_reporting).toBe(true);
  expect((await (await fetch(`${base}/v1/oauth/clients/${on.client_id}`)).json()).outcome_reporting).toBe(true);
  expect((await fetch(`${base}/v1/oauth/register`, json(registration({ outcome_reporting: "yes" })))).status).toBe(400);
  // The update path accepts and persists it too.
  const put = await fetch(`${base}/v1/oauth/register/${on.client_id}`, { method: "PUT", headers: { "content-type": "application/json", authorization: `Bearer ${on.registration_access_token}` }, body: JSON.stringify({ ...registration({ outcome_reporting: false }), client_id: on.client_id }) });
  expect(put.status).toBe(200);
  expect((await put.json()).outcome_reporting).toBe(false);
  expect((await (await fetch(`${base}/v1/oauth/clients/${on.client_id}`)).json()).outcome_reporting).toBe(false);
});

test("a persisted client without outcome_reporting keeps working and reads as false", async () => {
  await start();
  const { client } = await issue();
  const statePath = join(dataDir, "oauth", "state.json");
  const state = JSON.parse(readFileSync(statePath, "utf8"));
  delete state.clients[client.client_id].outcomeReporting;
  writeFileSync(statePath, JSON.stringify(state));
  expect((await (await fetch(`${base}/v1/oauth/clients/${client.client_id}`)).json()).outcome_reporting).toBe(false);
});

test("outcome reports: auth, validation, active is final, failed may become active", async () => {
  await start();
  const { accessToken, capabilityId } = await issue({ outcome_reporting: true });

  const pending = await read(capabilityId);
  expect(pending.status).toBe(404);
  expect(await pending.json()).toEqual({ status: "pending" });

  expect((await report(undefined, { status: "active" })).status).toBe(401);
  expect((await report("not-a-real-token-0000000000000000", { status: "active" })).status).toBe(401);
  expect((await report("bad token!", { status: "active" })).status).toBe(401);

  expect((await report(accessToken, { status: "done" })).status).toBe(400);
  expect((await report(accessToken, "{nope")).status).toBe(400);
  expect((await report(accessToken, { status: "failed", reason: 5 })).status).toBe(400);
  expect((await report(accessToken, { status: "failed", reason: "x".repeat(201) })).status).toBe(400);
  expect((await read(capabilityId)).status).toBe(404);

  expect((await report(accessToken, { status: "failed", reason: "  PDS rejected the DID document  " })).status).toBe(204);
  const failed = await read(capabilityId);
  expect(failed.status).toBe(200);
  expect(failed.headers.get("access-control-allow-origin")).toBe("https://app.did.md");
  expect(failed.headers.get("cache-control")).toBe("no-store");
  const failedBody = await failed.json();
  expect(failedBody).toMatchObject({ status: "failed", reason: "PDS rejected the DID document" });
  expect(Number.isNaN(Date.parse(failedBody.updatedAt))).toBe(false);

  expect((await report(accessToken, { status: "failed", reason: "x".repeat(200) })).status).toBe(204);
  expect((await (await read(capabilityId)).json()).reason).toBe("x".repeat(200));

  expect((await report(accessToken, { status: "active", reason: "ignored" })).status).toBe(204);
  const active = await (await read(capabilityId)).json();
  expect(active.status).toBe("active");
  expect(active.reason).toBeUndefined();

  expect((await report(accessToken, { status: "failed", reason: "late" })).status).toBe(204);
  expect((await (await read(capabilityId)).json()).status).toBe("active");
});

test("outcomes survive a server restart, and a different approval stays pending", async () => {
  await start();
  const { accessToken, capabilityId } = await issue();
  const other = await issue();
  expect((await report(accessToken, { status: "failed", reason: "boom" })).status).toBe(204);
  await stop(); await start();
  expect(await (await read(capabilityId)).json()).toMatchObject({ status: "failed", reason: "boom" });
  expect((await read(other.capabilityId)).status).toBe(404);
  // An access token does not outlive the restart (in-memory by design).
  expect((await report(accessToken, { status: "active" })).status).toBe(401);
});

test("outcomes older than 30 days are pruned on the next write", async () => {
  await start();
  const first = await issue();
  expect((await report(first.accessToken, { status: "failed", reason: "old" })).status).toBe(204);
  await stop();
  const path = join(dataDir, "oauth", "outcomes.json");
  const stored = JSON.parse(readFileSync(path, "utf8"));
  stored[first.capabilityId].updatedAt = new Date(Date.now() - 31 * 24 * 3600_000).toISOString();
  writeFileSync(path, JSON.stringify(stored));
  await start();
  const second = await issue(); // tokens do not survive a restart, so approve again
  expect((await report(second.accessToken, { status: "failed", reason: "new" })).status).toBe(204);
  expect((await read(first.capabilityId)).status).toBe(404);
  expect((await read(second.capabilityId)).status).toBe(200);
});
