import { afterAll, expect, test } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildGenesis, createIdentityMaterial } from "../packages/wallet/src/did-webvh.ts";
import { setTimeout as sleep } from "node:timers/promises";
import { spawn } from "./spawn.ts";

const port = 18_000 + Math.floor(Math.random() * 10_000);
const base = `http://127.0.0.1:${port}`;
const dataDir = mkdtempSync(join(tmpdir(), "did-md-atproto-did-"));
const server = spawn({
  cmd: [process.execPath, "server/server.ts"],
  cwd: new URL("..", import.meta.url).pathname,
  env: { ...process.env, PORT: String(port), DATA_DIR: dataDir, IDENTITY_DOMAIN: "did.md", IDENTITY_FETCH_BASE_URL: base },
  stdout: "ignore",
  stderr: "ignore",
});

async function ready(): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      if ((await fetch(`${base}/healthz`)).ok) return;
    } catch { /* still starting */ }
    await sleep(20);
  }
  throw new Error("did.md test server did not start");
}

afterAll(async () => {
  server.kill();
  await server.exited;
  rmSync(dataDir, { recursive: true, force: true });
});

test("atproto-did is 404 before publication and did:web after", async () => {
  await ready();
  const host = "atprotoalice.did.md";
  const missing = await fetch(`${base}/.well-known/atproto-did`, { headers: { host } });
  expect(missing.status).toBe(404);

  const identity = await createIdentityMaterial();
  const genesis = await buildGenesis({
    username: "atprotoalice",
    root: identity.root,
    sign: identity.sign,
    nextSpare: identity.nextSpare,
    domain: "did.md",
  });
  const published = await fetch(`${base}/.well-known/did.jsonl`, {
    method: "PUT",
    headers: { host, "content-type": "text/jsonl" },
    body: `${JSON.stringify(genesis)}\n`,
  });
  expect(published.status).toBe(201);

  const resolved = await fetch(`${base}/.well-known/atproto-did`, { headers: { host } });
  expect(resolved.status).toBe(200);
  expect(resolved.headers.get("content-type")).toContain("text/plain");
  const body = (await resolved.text()).trim();
  expect(body).toBe("did:web:atprotoalice.did.md");

  const write = await fetch(`${base}/.well-known/atproto-did`, {
    method: "PUT",
    headers: { host, "content-type": "text/plain" },
    body: "did:web:evil.example",
  });
  expect(write.status).toBe(405);
});
