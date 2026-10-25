import { afterAll, expect, test } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createIdentityMaterial } from "../packages/wallet/src/keys.ts";
import { createGenesisEntry, prepareLocationEntry } from "../packages/wallet/src/vh-ops.ts";
import { setTimeout as sleep } from "node:timers/promises";
import { spawn } from "./spawn.ts";

const port = 18_000 + Math.floor(Math.random() * 10_000);
const base = `http://127.0.0.1:${port}`;
const dataDir = mkdtempSync(join(tmpdir(), "did-md-connect-"));
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

// Mirrors the app.js "Connect" flow: an identity with no host is never PUT to a host as it is --
// prepareLocationEntry signs one additional update entry that makes its document name the place; the DID stays.
test("connecting an identity with no host publishes it at a real host", async () => {
  await ready();
  const identity = await createIdentityMaterial();
  const genesis = await createGenesisEntry({ root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare });
  expect(genesis.state.alsoKnownAs).toBeUndefined();

  const availability = await fetch(`${base}/v1/availability?username=frank`);
  expect(availability.ok).toBe(true);
  expect((await availability.json()).available).toBe(true);

  // versionTime is truncated to whole seconds; the location entry must still be later than genesis's even when
  // made in the same second (a real Connect click right after Create can be this fast).
  const source = `${JSON.stringify(genesis)}\n`;
  const prepared = await prepareLocationEntry({ entries: [genesis], src: "https://frank.did.md", masterSeed: identity.masterSeed, currentSpareIndex: 0 });
  expect(prepared.state.id).toBe(genesis.state.id);

  const published = await fetch(`${base}/.well-known/did.jsonl`, {
    method: "PUT", headers: { host: "frank.did.md", "content-type": "text/jsonl" },
    body: `${source}${JSON.stringify(prepared.entry)}\n`,
  });
  expect(published.status).toBe(201);

  const resolved = await fetch(`${base}/.well-known/did.jsonl`, { headers: { host: "frank.did.md" } });
  expect(resolved.status).toBe(200);
  const lines = (await resolved.text()).trim().split("\n");
  expect(lines).toHaveLength(2);
  expect(JSON.parse(lines[1]!).state.id).toBe(genesis.state.id);

  const byScid = await fetch(`${base}/log?scid=${genesis.state.id.slice("did:vh:".length)}`, { headers: { host: "anywhere.did.md" } });
  expect(byScid.status).toBe(200);

  const takenNow = await fetch(`${base}/v1/availability?username=frank`);
  expect((await takenNow.json()).available).toBe(false);
});
