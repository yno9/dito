import { afterAll, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { formatReport, runConformance } from "../packages/webvh/src/index.ts";

// did.md's own server against the protocol's conformance suite: the server
// serves any `<name>.did.md` by Host header, so the target rewrites URLs to the
// local port and sets Host -- exactly what a real deployment does via DNS.
const port = 18_000 + Math.floor(Math.random() * 10_000);
const base = `http://127.0.0.1:${port}`;
const dataDir = mkdtempSync(join(tmpdir(), "did-md-conformance-"));
const server = Bun.spawn({
  cmd: [process.execPath, "server/server.ts"], cwd: new URL("..", import.meta.url).pathname,
  env: { ...process.env, PORT: String(port), DATA_DIR: dataDir, IDENTITY_FETCH_BASE_URL: base },
  stdout: "ignore", stderr: "ignore",
});
afterAll(async () => { server.kill(); await server.exited; rmSync(dataDir, { recursive: true, force: true }); });

async function ready() {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try { if ((await fetch(`${base}/healthz`)).ok) return; } catch { /* starting */ }
    await Bun.sleep(20);
  }
  throw new Error("server did not start");
}

test("did.md's host conforms to webvh-hosting/1", async () => {
  await ready();
  let counter = 0;
  const results = await runConformance({
    newLocation: () => `conf-${Date.now().toString(36)}${counter++}.did.md`,
    fetch: ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      const headers = new Headers(init?.headers);
      headers.set("host", url.host);
      return fetch(`${base}${url.pathname}${url.search}`, { ...init, headers });
    }) as typeof fetch,
  });
  const report = formatReport(results);
  if (!report.ok) console.log(report.text);
  expect(report.ok).toBe(true);
  expect(results.length).toBeGreaterThanOrEqual(14);
});
