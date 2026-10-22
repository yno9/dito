import { afterAll, beforeAll, expect, test } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createLog, serializeLog, keyFromPrivateKey, Ed25519Signer, nextKeyHash } from "../packages/webvh/src/index.ts";
import { setTimeout as sleep } from "node:timers/promises";
import { spawn } from "./spawn.ts";
import { Gate, HourlyCount, Refusal } from "../server/host/limits.ts";

// The host's limits, which v2 admin changes while it runs: they are read from the snapshot the admin writes (here a file we write),
// and the operator's two operations and numbers sit behind a token on the host's own port.
const port = 19_000 + Math.floor(Math.random() * 10_000);
const base = `http://127.0.0.1:${port}`;
const root = mkdtempSync(join(tmpdir(), "did-md-limits-"));
const dataDir = join(root, "data"), configDir = join(root, "config"), tokenFile = join(root, "token");
mkdirSync(configDir);
writeFileSync(tokenFile, "operator-token\n");
const server = spawn({
  cmd: [process.execPath, "server/host/http-server.ts"], cwd: new URL("..", import.meta.url).pathname,
  env: { ...process.env, PORT: String(port), DATA_DIR: dataDir, V2_ADMIN_CONFIG_DIR: configDir, V2_ADMIN_TOKEN_FILE: tokenFile, V2_ADMIN_SETTINGS_INTERVAL_MS: "50" },
  stdout: "ignore", stderr: "ignore",
});
afterAll(async () => { server.kill(); await server.exited; rmSync(root, { recursive: true, force: true }); });
beforeAll(async () => {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try { if ((await fetch(`${base}/healthz`)).ok) return; } catch { /* starting */ }
    await sleep(20);
  }
  throw new Error("server did not start");
});

let version = 0;
async function setLimits(values: Record<string, unknown>) {
  version += 1;
  writeFileSync(join(configDir, "dito.json"), JSON.stringify({ version, updatedAt: new Date().toISOString(), values }));
  await sleep(250); // the host looks again every 50 ms
}
const viaHost = ((input: RequestInfo | URL, init?: RequestInit) => {
  const url = new URL(String(input));
  const headers = new Headers(init?.headers); headers.set("host", url.host);
  return fetch(`${base}${url.pathname}${url.search}`, { ...init, headers });
}) as typeof fetch;
const key = keyFromPrivateKey(crypto.getRandomValues(new Uint8Array(32)));
const next = keyFromPrivateKey(crypto.getRandomValues(new Uint8Array(32)));
async function publish(name: string) {
  const created = await createLog({
    domain: `${name}.did.md`, signer: new Ed25519Signer(key), updateKeys: [key.multikey], nextKeyHashes: [await nextKeyHash(next.multikey)],
    verificationMethods: [{ id: "#k", type: "Multikey", publicKeyMultibase: key.multikey }], authentication: ["#k"],
  });
  return viaHost(`https://${name}.did.md/.well-known/did.jsonl`, { method: "PUT", headers: { "content-type": "text/jsonl" }, body: serializeLog(created.log) });
}
const unique = (prefix: string) => `${prefix}${Date.now().toString(36)}${Math.floor(Math.random() * 1e4)}`;
const admin = (path: string, init: RequestInit = {}, token: string | null = "operator-token") => fetch(`${base}${path}`, { ...init, headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), "content-type": "application/json", ...(init.headers as Record<string, string>) } });

test("a log or a body over the size limit is refused, and a new limit applies without a restart", async () => {
  await setLimits({ "limits.maxLogBytes": 4096 });
  const big = "x".repeat(5000);
  const put = (body: string) => viaHost("https://sizes.did.md/.well-known/did.jsonl", { method: "PUT", headers: { "content-type": "text/jsonl" }, body });
  let refused = await put(big);
  expect([refused.status, (await refused.text()).trim()]).toEqual([400, "request body is too large"]);
  await setLimits({ "limits.maxLogBytes": 16384 });
  refused = await put(big); // now it is read as a log, and is not one
  expect((await refused.text()).trim()).not.toBe("request body is too large");
  await setLimits({});
});

test("only so many new identities an hour, from everyone; an identity already there is still read", async () => {
  await setLimits({ "limits.createPerHour": 2 });
  const names = [unique("rate-a"), unique("rate-b"), unique("rate-c")];
  expect((await publish(names[0]!)).status).toBe(201);
  expect((await publish(names[1]!)).status).toBe(201);
  const third = await publish(names[2]!);
  expect([third.status, third.headers.get("retry-after")]).toEqual([429, "300"]);
  expect((await viaHost(`https://${names[0]}.did.md/.well-known/did.jsonl`)).status).toBe(200);
  await setLimits({ "limits.createPerHour": 1000 });
  expect((await publish(names[2]!)).status).toBe(201); // the limit was raised while running
});

test("a host that is full takes no new identity", async () => {
  await setLimits({ "limits.maxIdentities": 1 });
  const refused = await publish(unique("full"));
  expect([refused.status, (await refused.text()).trim()]).toEqual([503, "this host cannot take more identities"]);
  await setLimits({});
});

test("names the operator adds are reserved at once", async () => {
  await setLimits({ "names.reserved": ["zebra-corp"] });
  const refused = await publish("zebra-corp");
  expect([refused.status, (await refused.text()).trim()]).toEqual([400, "this name is reserved"]);
  await setLimits({});
});

test("the operator's numbers and operations answer only the right token, and are not reachable by a name or a path of the public host", async () => {
  expect((await admin("/admin/metrics", {}, null)).status).toBe(404);
  expect((await admin("/admin/metrics", {}, "wrong")).status).toBe(404);
  const metrics = await (await admin("/admin/metrics")).json() as { metrics: Record<string, { value: number }> };
  expect(metrics.metrics.identities!.value).toBeGreaterThan(0);
  expect(metrics.metrics.refusedRate!.value).toBeGreaterThan(0);
  expect((await admin("/admin/nothing")).status).toBe(404);
});

test("stopping an identity takes its documents down and closes it to writes; letting it back restores both; nothing is deleted", async () => {
  const name = unique("stop");
  expect((await publish(name)).status).toBe(201);
  const url = `https://${name}.did.md/.well-known/did.jsonl`;
  const run = (action: string, params: unknown) => admin(`/admin/actions/${action}`, { method: "POST", body: JSON.stringify({ action, params }) });
  expect((await run("stop-identity", { username: name, reason: "abuse" })).status).toBe(200);
  expect((await viaHost(url)).status).toBe(404);
  expect((await viaHost(`https://${name}.did.md/.well-known/atproto-did`)).status).toBe(404);
  const write = await publish(name);
  expect([write.status, (await write.text()).trim()]).toEqual([403, "this identity has been stopped by the operator"]);
  expect((await run("stop-identity", { username: name })).status).toBe(200); // already stopped: said, not an error
  expect((await run("release-identity", { username: name })).status).toBe(200);
  expect((await viaHost(url)).status).toBe(200);
  expect((await run("stop-identity", { username: "no-such-identity" })).status).toBe(404);
  expect((await run("stop-identity", { username: "Bad Name!" })).status).toBe(400);
  expect((await admin("/admin/actions/stop-identity", { method: "POST", body: "{}" }, null)).status).toBe(404);
});

test("the gate lets only so many through at once and turns the rest away at once", async () => {
  const gate = new Gate();
  let release!: () => void;
  const held = gate.run(1, () => new Promise<void>(resolve => { release = resolve; }));
  await expect(gate.run(1, async () => 1)).rejects.toMatchObject({ status: 503 });
  await expect(gate.run(2, async () => "second")).resolves.toBe("second");
  release(); await held;
  expect(await gate.run(1, async () => "free again")).toBe("free again");
  expect(new Refusal(429, "x").retryAfterSeconds).toBeUndefined();
});

test("the hourly count forgets what is older than an hour", () => {
  let now = 0;
  const count = new HourlyCount(() => now);
  count.add(); count.add();
  expect(count.count()).toBe(2);
  now = 3_600_001;
  expect(count.count()).toBe(0);
});

test("the manifest the admin reads describes exactly the settings the host reads", async () => {
  const { LIMIT_SETTINGS } = await import("../server/host/limits.ts");
  const { readFileSync } = await import("node:fs");
  const manifest = JSON.parse(readFileSync(new URL("../admin.manifest.json", import.meta.url), "utf8")) as { settings: Record<string, Record<string, unknown>> };
  expect(Object.keys(manifest.settings).sort()).toEqual(Object.keys(LIMIT_SETTINGS).sort());
  for (const [key, def] of Object.entries(LIMIT_SETTINGS)) {
    for (const field of ["type", "default", "min", "max", "item", "maxItems", "maxLength", "pattern"] as const) expect([key, field, manifest.settings[key]![field]]).toEqual([key, field, (def as unknown as Record<string, unknown>)[field]]);
  }
});
