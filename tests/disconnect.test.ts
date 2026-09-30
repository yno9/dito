import { afterAll, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildGenesis, createDataIntegrityProof, createIdentityMaterial } from "../packages/wallet/src/did-webvh.ts";

const port = 18_000 + Math.floor(Math.random() * 10_000);
const base = `http://127.0.0.1:${port}`;
const dataDir = mkdtempSync(join(tmpdir(), "did-md-disconnect-"));
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

async function publishGenesis(username: string) {
  const identity = await createIdentityMaterial();
  const entry = await buildGenesis({
    username, displayName: "", root: identity.root, sign: identity.sign,
    nextSpare: identity.nextSpare, api: base, domain: "did.md",
  });
  const headers = { host: `${username}.did.md` };
  const published = await fetch(`${base}/.well-known/did.jsonl`, {
    method: "PUT", headers: { ...headers, "content-type": "text/jsonl" },
    body: `${JSON.stringify(entry)}\n`,
  });
  expect(published.status).toBe(201);
  return { identity, entry, headers };
}

async function disconnectProof(did: string, signIdentity: { privateKey: Uint8Array; multikey: string }, created = new Date().toISOString()) {
  const document = { did };
  const proof = await createDataIntegrityProof(document, {
    privateKey: signIdentity.privateKey,
    verificationMethod: `did:key:${signIdentity.multikey}#${signIdentity.multikey}`,
    proofPurpose: "assertionMethod", created,
  });
  return { ...document, proof };
}

test("DELETE removes a published did.jsonl when signed by a current update key", async () => {
  await ready();
  const { identity, entry, headers } = await publishGenesis("bob");
  const removed = await fetch(`${base}/.well-known/did.jsonl`, {
    method: "DELETE", headers: { ...headers, "content-type": "application/json" },
    body: JSON.stringify(await disconnectProof(entry.state.id, identity.sign)),
  });
  expect(removed.status).toBe(204);
  const after = await fetch(`${base}/.well-known/did.jsonl`, { headers });
  expect(after.status).toBe(404);
});

test("DELETE is rejected when signed by a key that is not an active update key", async () => {
  await ready();
  const { entry, headers } = await publishGenesis("carol");
  const impostor = await createIdentityMaterial();
  const removed = await fetch(`${base}/.well-known/did.jsonl`, {
    method: "DELETE", headers: { ...headers, "content-type": "application/json" },
    body: JSON.stringify(await disconnectProof(entry.state.id, impostor.sign)),
  });
  expect(removed.status).toBe(400);
  const after = await fetch(`${base}/.well-known/did.jsonl`, { headers });
  expect(after.status).toBe(200);
});

test("DELETE is rejected when the proof is stale", async () => {
  await ready();
  const { identity, entry, headers } = await publishGenesis("dana");
  const stale = new Date(Date.now() - 10 * 60_000).toISOString();
  const removed = await fetch(`${base}/.well-known/did.jsonl`, {
    method: "DELETE", headers: { ...headers, "content-type": "application/json" },
    body: JSON.stringify(await disconnectProof(entry.state.id, identity.sign, stale)),
  });
  expect(removed.status).toBe(400);
  const after = await fetch(`${base}/.well-known/did.jsonl`, { headers });
  expect(after.status).toBe(200);
});

test("DELETE is rejected when the document.did does not match the published DID", async () => {
  await ready();
  const { identity, headers } = await publishGenesis("erin");
  const removed = await fetch(`${base}/.well-known/did.jsonl`, {
    method: "DELETE", headers: { ...headers, "content-type": "application/json" },
    body: JSON.stringify(await disconnectProof("did:webvh:wrong:erin.did.md", identity.sign)),
  });
  expect(removed.status).toBe(400);
  const after = await fetch(`${base}/.well-known/did.jsonl`, { headers });
  expect(after.status).toBe(200);
});

test("DELETE on a DID that was never published returns 404", async () => {
  await ready();
  const identity = await createIdentityMaterial();
  const headers = { host: "neverconnected.did.md" };
  const removed = await fetch(`${base}/.well-known/did.jsonl`, {
    method: "DELETE", headers: { ...headers, "content-type": "application/json" },
    body: JSON.stringify(await disconnectProof("did:webvh:x:neverconnected.did.md", identity.sign)),
  });
  expect(removed.status).toBe(404);
});
