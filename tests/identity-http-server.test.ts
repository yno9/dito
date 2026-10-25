import { afterAll, expect, test } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { formatReport, serializeVhLog, runVhConformance } from "../packages/vh/src/index.ts";
import { vhLogAt } from "./helpers/vh-log.ts";
import { setTimeout as sleep } from "node:timers/promises";
import { spawn } from "./spawn.ts";

// The VPS entry point (server/host/http-server.ts): conforms to the protocol
// and makes public reads CDN-cacheable while never caching writes or 404s.
const port = 18_000 + Math.floor(Math.random() * 10_000);
const base = `http://127.0.0.1:${port}`;
const dataDir = mkdtempSync(join(tmpdir(), "did-md-http-"));
const server = spawn({
  cmd: [process.execPath, "server/host/http-server.ts"], cwd: new URL("..", import.meta.url).pathname,
  env: { ...process.env, PORT: String(port), DATA_DIR: dataDir },
  stdout: "ignore", stderr: "ignore",
});
afterAll(async () => { server.kill(); await server.exited; rmSync(dataDir, { recursive: true, force: true }); });
async function ready() {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try { if ((await fetch(`${base}/healthz`)).ok) return; } catch { /* starting */ }
    await sleep(20);
  }
  throw new Error("server did not start");
}
const viaHost = ((input: RequestInfo | URL, init?: RequestInit) => {
  const url = new URL(String(input));
  const headers = new Headers(init?.headers);
  headers.set("host", url.host);
  return fetch(`${base}${url.pathname}${url.search}`, { ...init, headers });
}) as typeof fetch;

test("the VPS host passes the protocol conformance suite, against the real file store", async () => {
  await ready();
  let n = 0;
  const target = { newLocation: () => `vh${Date.now().toString(36)}${n++}.did.md`, fetch: viaHost };
  const results = await runVhConformance(target);
  const report = formatReport(results);
  if (!report.ok) console.log(report.text);
  expect(report.ok).toBe(true);
  expect(results.length).toBeGreaterThanOrEqual(12);
});

test("public reads are CDN-cacheable (s-maxage), 404s and writes are not", async () => {
  await ready();
  const host = `cache${Date.now().toString(36)}.did.md`;
  const created = await vhLogAt(host);
  const url = `https://${host}/.well-known/did.jsonl`;
  const missing = await viaHost(url);
  expect(missing.status).toBe(404);
  expect(missing.headers.get("cache-control")).toBe("no-store");

  const put = await viaHost(url, { method: "PUT", headers: { "content-type": "text/jsonl" }, body: serializeVhLog(created.log) });
  expect(put.status).toBe(201);
  expect(put.headers.get("cache-control") ?? "").not.toContain("s-maxage");

  const read = await viaHost(url);
  expect(read.status).toBe(200);
  expect(read.headers.get("cache-control")).toMatch(/public.*s-maxage=30/);
  expect(read.headers.get("access-control-allow-origin")).toBe("*");
  for (const resource of ["did.json"]) {
    const other = await viaHost(`https://${host}/.well-known/${resource}`);
    expect(other.headers.get("cache-control")).toMatch(/s-maxage=30/);
  }
});

test("a name that sounds like the service (postmaster, didmail, support ...) cannot be registered, and says so when asked", async () => {
  await ready();
  const publish = async (host: string) => {
    const created = await vhLogAt(host);
    return viaHost(`https://${host}/.well-known/did.jsonl`, { method: "PUT", headers: { "content-type": "text/jsonl" }, body: serializeVhLog(created.log) });
  };
  for (const name of ["postmaster", "didmail", "support", "mailer-daemon", "xn--mail-6za"]) {
    const refused = await publish(`${name}.did.md`);
    expect([name, refused.status, (await refused.text()).trim()]).toEqual([name, 400, "this name is reserved"]);
    const asked = await (await viaHost(`https://api.did.md/v1/availability?username=${name}`)).json() as { available: boolean; reserved?: boolean };
    expect([name, asked.available, asked.reserved]).toEqual([name, false, true]);
  }
  // an ordinary name is unaffected, and says nothing about being reserved
  const host = `ordinary${Date.now().toString(36)}.did.md`
  expect((await publish(host)).status).toBe(201);
  const taken = await (await viaHost(`https://api.did.md/v1/availability?username=${host.split(".")[0]}`)).json() as { available: boolean; reserved?: boolean };
  expect([taken.available, taken.reserved]).toEqual([false, undefined]);
});
