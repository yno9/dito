import { afterAll, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { formatReport, runConformance, createLog, serializeLog, keyFromPrivateKey, Ed25519Signer, nextKeyHash } from "../packages/webvh/src/index.ts";

// The VPS entry point (server/host/http-server.ts): conforms to the protocol
// and makes public reads CDN-cacheable while never caching writes or 404s.
const port = 18_000 + Math.floor(Math.random() * 10_000);
const base = `http://127.0.0.1:${port}`;
const dataDir = mkdtempSync(join(tmpdir(), "did-md-http-"));
const server = Bun.spawn({
  cmd: [process.execPath, "server/host/http-server.ts"], cwd: new URL("..", import.meta.url).pathname,
  env: { ...process.env, PORT: String(port), DATA_DIR: dataDir },
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
const viaHost = ((input: RequestInfo | URL, init?: RequestInit) => {
  const url = new URL(String(input));
  const headers = new Headers(init?.headers);
  headers.set("host", url.host);
  return fetch(`${base}${url.pathname}${url.search}`, { ...init, headers });
}) as typeof fetch;

test("the VPS host passes the protocol conformance suite", async () => {
  await ready();
  let n = 0;
  const report = formatReport(await runConformance({ newLocation: () => `vps${Date.now().toString(36)}${n++}.did.md`, fetch: viaHost }));
  if (!report.ok) console.log(report.text);
  expect(report.ok).toBe(true);
});

test("public reads are CDN-cacheable (s-maxage), 404s and writes are not", async () => {
  await ready();
  const key = keyFromPrivateKey(crypto.getRandomValues(new Uint8Array(32)));
  const next = keyFromPrivateKey(crypto.getRandomValues(new Uint8Array(32)));
  const host = `cache${Date.now().toString(36)}.did.md`;
  const created = await createLog({
    domain: host, signer: new Ed25519Signer(key), updateKeys: [key.multikey], nextKeyHashes: [await nextKeyHash(next.multikey)],
    verificationMethods: [{ id: "#k", type: "Multikey", publicKeyMultibase: key.multikey }], authentication: ["#k"],
  });
  const url = `https://${host}/.well-known/did.jsonl`;
  const missing = await viaHost(url);
  expect(missing.status).toBe(404);
  expect(missing.headers.get("cache-control")).toBe("no-store");

  const put = await viaHost(url, { method: "PUT", headers: { "content-type": "text/jsonl" }, body: serializeLog(created.log) });
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
