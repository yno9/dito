import { afterAll, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildGenesis, createIdentityMaterial, preparePortableImport } from "../packages/wallet/src/did-webvh.ts";

const port = 18_000 + Math.floor(Math.random() * 10_000);
const base = `http://127.0.0.1:${port}`;
const dataDir = mkdtempSync(join(tmpdir(), "did-md-connect-"));
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

// Mirrors the app.js "Connect" flow: a provisional (did.invalid) genesis is
// never PUT to a host directly -- preparePortableImport signs one additional
// portability entry that gives it its first real, did:webvh-compatible home.
test("connecting a provisional did.invalid identity publishes it at a real host", async () => {
  await ready();
  const identity = await createIdentityMaterial();
  const genesis = await buildGenesis({
    username: "did", root: identity.root, sign: identity.sign,
    nextSpare: identity.nextSpare, domain: "invalid",
  });
  expect(genesis.state.id.endsWith(":did.invalid")).toBe(true);

  const availability = await fetch(`${base}/v1/availability?username=frank`);
  expect(availability.ok).toBe(true);
  expect((await availability.json()).available).toBe(true);

  // versionTime is truncated to whole seconds; preparePortableImport must
  // still bump past genesis's versionTime even when called in the same
  // second (a real Connect click right after Create can be this fast).
  const source = `${JSON.stringify(genesis)}\n`;
  const prepared = await preparePortableImport({ entries: [genesis], username: "frank", domain: "did.md", masterSeed: identity.masterSeed });
  expect(prepared.did.endsWith(":frank.did.md")).toBe(true);

  const published = await fetch(`${base}/.well-known/did.jsonl`, {
    method: "PUT", headers: { host: "frank.did.md", "content-type": "text/jsonl" },
    body: `${source}${JSON.stringify(prepared.entry)}\n`,
  });
  expect(published.status).toBe(201);

  const resolved = await fetch(`${base}/.well-known/did.jsonl`, { headers: { host: "frank.did.md" } });
  expect(resolved.status).toBe(200);
  const lines = (await resolved.text()).trim().split("\n");
  expect(lines).toHaveLength(2);
  expect(JSON.parse(lines[1]!).state.id).toBe(prepared.did);

  const takenNow = await fetch(`${base}/v1/availability?username=frank`);
  expect((await takenNow.json()).available).toBe(false);
});
