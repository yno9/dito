// The CLI on a did:vh identity, end to end against did.md's host (in-process): new, connect, service, rotate, publish, verify by
// watcher, fetch, the version memory, export/import, unpublish.
import { afterEach, beforeEach, expect, test } from "vitest";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run } from "../packages/cli/src/cli.ts";
import { freshHost, resetHost, viaHost } from "./helpers/vh-host.ts";

const realFetch = globalThis.fetch;
beforeEach(() => { freshHost(); globalThis.fetch = viaHost; });
afterEach(() => { globalThis.fetch = realFetch; resetHost(); });

function harness(env: Record<string, string | undefined> = {}) {
  let out = "", err = "";
  return { io: { out: (t: string) => { out += t; }, err: (t: string) => { err += t; }, env }, get out() { return out; }, get err() { return err; } };
}
const dir = () => mkdtempSync(join(tmpdir(), "dito-cli-vh-"));

async function created() {
  const d = dir(), log = join(d, "did.jsonl"), state = dir();
  const made = harness();
  expect(await run(["new", "--method", "vh", "--log", log, "--json"], made.io)).toBe(0);
  const info = JSON.parse(made.out);
  return { d, log, state, info, env: { DITO_MNEMONIC: info.mnemonic as string, XDG_STATE_HOME: state } };
}

test("new --method vh makes a did:vh identity with no host; show and verify read it without a secret", async () => {
  const { log, info } = await created();
  expect(info).toMatchObject({ method: "did:vh", provisional: true, entries: 1, locations: [] });
  expect(info.did).toMatch(/^did:vh:/);
  expect(info.mnemonic.split(" ")).toHaveLength(24);
  expect(JSON.parse(readFileSync(log, "utf8").split("\n")[0]!).parameters.method).toBe("did:vh:1.0");
  const shown = harness();
  expect(await run(["show", "--log", log, "--json"], shown.io)).toBe(0);
  expect(JSON.parse(shown.out)).toMatchObject({ did: info.did, method: "did:vh", entries: 1, deactivated: false });
  expect(await run(["verify", "--log", log], harness().io)).toBe(0);
  expect(await run(["new", "--method", "vh", "--log", log], harness().io)).toBe(2);
  expect(await run(["new", "--method", "nope", "--log", join(dir(), "x.jsonl")], harness().io)).toBe(2);
});

test("connect, service, rotate: the host and the file agree after each, and the DID never changes", async () => {
  const { log, info, env } = await created();
  const connected = harness(env);
  expect(await run(["connect", "alice", "--log", log, "--json"], connected.io)).toBe(0);
  expect(JSON.parse(connected.out)).toMatchObject({ did: info.did, logUrl: "https://alice.did.md/.well-known/did.jsonl", locations: ["https://alice.did.md"], entries: 2 });
  expect(await (await viaHost("https://alice.did.md/.well-known/did.jsonl")).text()).toBe(readFileSync(log, "utf8"));
  expect(await run(["service", "add", "#files", "relativeRef", "https://alice.did.md/", "--log", log], harness(env).io)).toBe(0);
  expect(await run(["rotate", "--log", log], harness(env).io)).toBe(0);
  expect(await (await viaHost("https://alice.did.md/.well-known/did.jsonl")).text()).toBe(readFileSync(log, "utf8"));
  const web = await (await viaHost("https://alice.did.md/.well-known/did.json")).json();
  expect(web.service.some((s: any) => s.id === "#files")).toBe(true);
  const shown = harness();
  await run(["show", "--log", log, "--json"], shown.io);
  expect(JSON.parse(shown.out)).toMatchObject({ did: info.did, entries: 4, locations: ["https://alice.did.md"] });
});

test("publish needs no secret: it puts the log where its own document says; --local updates keep the host untouched until then", async () => {
  const { log, env } = await created();
  await run(["connect", "alice", "--log", log], harness(env).io);
  const before = await (await viaHost("https://alice.did.md/.well-known/did.jsonl")).text();
  expect(await run(["rotate", "--local", "--log", log], harness(env).io)).toBe(0);
  expect(await (await viaHost("https://alice.did.md/.well-known/did.jsonl")).text()).toBe(before);
  const published = harness();
  expect(await run(["publish", "--log", log, "--json"], published.io)).toBe(0);
  expect(JSON.parse(published.out)).toMatchObject({ verified: true, logUrl: "https://alice.did.md/.well-known/did.jsonl" });
  expect(await (await viaHost("https://alice.did.md/.well-known/did.jsonl")).text()).toBe(readFileSync(log, "utf8"));
  // No location: nothing to publish to.
  const bare = await created();
  const refused = harness();
  expect(await run(["publish", "--log", bare.log], refused.io)).toBe(2);
  expect(refused.err).toMatch(/names no location/);
});

test("a did:vh DID names no location: verify and fetch need --watcher or --src", async () => {
  const { log, info, env, d } = await created();
  await run(["connect", "alice", "--log", log], harness(env).io);
  const lost = harness(env);
  expect(await run(["verify", info.did], lost.io)).toBe(2);
  expect(lost.err).toMatch(/--watcher/);
  expect(await run(["verify", info.did, "--watcher", "https://anywhere.did.md"], harness(env).io)).toBe(0);
  expect(await run(["verify", info.did, "--src", "https://alice.did.md"], harness(env).io)).toBe(0);
  const missing = harness(env);
  expect(await run(["verify", info.did, "--src", "https://nobody.did.md"], missing.io)).toBe(1);
  const copy = join(d, "copy.jsonl");
  expect(await run(["fetch", info.did, "--watcher", "https://anywhere.did.md", "--log", copy], harness(env).io)).toBe(0);
  expect(readFileSync(copy, "utf8")).toBe(readFileSync(log, "utf8"));
  expect(await run(["fetch", info.did, "--watcher", "https://anywhere.did.md", "--log", copy], harness(env).io)).toBe(2);
});

test("the version memory covers did:vh: an older copy is refused with the way out, forget and --no-memory lift it", async () => {
  const { log, info, env } = await created();
  await run(["connect", "alice", "--log", log], harness(env).io);
  const older = readFileSync(log, "utf8");
  await run(["rotate", "--log", log], harness(env).io);
  const watcher = ["--watcher", "https://anywhere.did.md"];
  expect(await run(["verify", info.did, ...watcher], harness(env).io)).toBe(0);
  // The host is restored from a backup: it serves the log as it was before the rotation.
  const { setIdentityStore } = await import("../server/host/identity-host.ts");
  const { MemoryStore } = await import("./helpers/vh-host.ts");
  const restored = new MemoryStore();
  setIdentityStore(restored);
  expect((await viaHost("https://alice.did.md/.well-known/did.jsonl", { method: "PUT", body: older })).status).toBe(201);
  const refused = harness(env);
  expect(await run(["verify", info.did, ...watcher], refused.io)).toBe(1);
  expect(refused.err).toMatch(/older/);
  expect(refused.err).toContain(`dito forget ${info.did}`);
  expect(await run(["verify", info.did, ...watcher, "--no-memory"], harness(env).io)).toBe(0);
  const forgot = harness(env);
  expect(await run(["forget", info.did, "--json"], forgot.io)).toBe(0);
  expect(JSON.parse(forgot.out).forgotten).toBe(true);
  expect(await run(["verify", info.did, ...watcher], harness(env).io)).toBe(0);
  expect(await run(["forget", info.did, "--no-memory"], harness(env).io)).toBe(2);
});

test("export --jwe and import carry a did:vh identity; export writes the log to serve", async () => {
  const { log, env, d } = await created();
  await run(["connect", "alice", "--log", log], harness(env).io);
  const exported = harness(env);
  expect(await run(["export", "--jwe", "--out", d, "--log", log, "--json"], exported.io)).toBe(0);
  const { wrote } = JSON.parse(exported.out);
  const restored = join(d, "restored.jsonl");
  expect(await run(["import", wrote, "--log", restored, "--json"], harness(env).io)).toBe(0);
  expect(readFileSync(restored, "utf8")).toBe(readFileSync(log, "utf8"));
  expect(await run(["import", wrote, "--log", join(d, "wrong.jsonl")], harness({ DITO_MNEMONIC: (await created()).env.DITO_MNEMONIC }).io)).not.toBe(0);
  const out = dir();
  expect(await run(["export", "--out", out, "--log", log], harness().io)).toBe(0);
  expect(readFileSync(join(out, ".well-known", "did.jsonl"), "utf8")).toBe(readFileSync(log, "utf8"));
  expect(() => readFileSync(join(out, ".well-known", "did.json"))).toThrow();
});

test("unpublish takes the log down from the host; the file stays and publishes again", async () => {
  const { log, env } = await created();
  await run(["connect", "alice", "--log", log], harness(env).io);
  expect(await run(["unpublish", "--log", log], harness(env).io)).toBe(0);
  expect((await viaHost("https://alice.did.md/.well-known/did.jsonl")).status).toBe(404);
  expect(await run(["publish", "--log", log], harness().io)).toBe(0);
  expect((await viaHost("https://alice.did.md/.well-known/did.jsonl")).status).toBe(200);
});

test("the did:webvh commands are untouched by all this: a webvh log still goes to the webvh code", async () => {
  const d = dir(), log = join(d, "did.jsonl");
  const made = harness();
  expect(await run(["new", "--log", log, "--json"], made.io)).toBe(0);
  expect(JSON.parse(made.out).did).toMatch(/^did:webvh:/);
  expect(await run(["verify", "--log", log], harness().io)).toBe(0);
});
