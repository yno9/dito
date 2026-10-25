// The CLI, end to end against did.md's host (in-process): new, connect, service, rotate, publish, verify by
// watcher, fetch, the version memory, export/import, unpublish; and the offline commands (domain, export, --local).
import { afterEach, beforeEach, expect, test } from "vitest";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
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
const dir = () => mkdtempSync(join(tmpdir(), "dito-cli-"));

async function created() {
  const d = dir(), log = join(d, "did.jsonl"), state = dir();
  const made = harness();
  expect(await run(["new", "--log", log, "--json"], made.io)).toBe(0);
  const info = JSON.parse(made.out);
  return { d, log, state, info, env: { DITO_MNEMONIC: info.mnemonic as string, XDG_STATE_HOME: state } };
}

test("new makes a did:vh identity with no host; show and verify read it without a secret", async () => {
  const { log, info } = await created();
  expect(info).toMatchObject({ method: "did:vh", provisional: true, entries: 1, locations: [] });
  expect(info.did).toMatch(/^did:vh:/);
  expect(info.mnemonic.split(" ")).toHaveLength(24);
  expect(JSON.parse(readFileSync(log, "utf8").split("\n")[0]!).parameters.method).toBe("did:vh:1.0");
  const shown = harness();
  expect(await run(["show", "--log", log, "--json"], shown.io)).toBe(0);
  expect(JSON.parse(shown.out)).toMatchObject({ did: info.did, method: "did:vh", entries: 1, deactivated: false });
  expect(await run(["verify", "--log", log], harness().io)).toBe(0);
  expect(await run(["new", "--log", log], harness().io)).toBe(2); // refuses to overwrite
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

test("export --jwe and import carry a did:vh identity; export writes the log and the did:web document to serve", async () => {
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
  expect(JSON.parse(readFileSync(join(out, ".well-known", "did.json"), "utf8")).id).toBe("did:web:alice.did.md");
});

test("unpublish takes the log down from the host; the file stays and publishes again", async () => {
  const { log, env } = await created();
  await run(["connect", "alice", "--log", log], harness(env).io);
  expect(await run(["unpublish", "--log", log], harness(env).io)).toBe(0);
  expect((await viaHost("https://alice.did.md/.well-known/did.jsonl")).status).toBe(404);
  expect(await run(["publish", "--log", log], harness().io)).toBe(0);
  expect((await viaHost("https://alice.did.md/.well-known/did.jsonl")).status).toBe(200);
});


test("new -> show -> verify -> offline service/rotate, all from files, with --json for agents", async () => {
  const { log, info } = await created();
  expect(info.mnemonic.split(" ")).toHaveLength(24);
  const env = { DITO_MNEMONIC: info.mnemonic as string };
  const added = harness(env);
  expect(await run(["service", "add", "#files", "relativeRef", "https://example.com/", "--log", log, "--local", "--json"], added.io)).toBe(0);
  expect(JSON.parse(added.out).entries).toBe(2);
  expect(await run(["rotate", "--log", log, "--local"], harness(env).io)).toBe(0);
  const final = harness();
  await run(["show", "--log", log, "--json"], final.io);
  const doc = JSON.parse(final.out);
  expect(doc.entries).toBe(3);
  expect(doc.document.service.some((s: any) => s.id === "#files")).toBe(true);
  expect(await run(["service", "remove", "#files", "--log", log, "--local"], harness(env).io)).toBe(0);
});

test("failure modes: refuses to overwrite, wrong mnemonic, tampered log, missing secrets, unknown command", async () => {
  const { d, log, info } = await created();
  expect(await run(["rotate", "--log", log, "--local"], harness().io)).toBe(2); // no mnemonic anywhere
  const other = await created();
  const wrong = harness({ DITO_MNEMONIC: other.info.mnemonic });
  expect(await run(["rotate", "--log", log, "--local"], wrong.io)).toBe(1);
  expect(wrong.err).toMatch(/Root Key/);
  writeFileSync(log, readFileSync(log, "utf8").replace("\"authentication\"", "\"name\":\"tampered\",\"authentication\""));
  expect(await run(["verify", "--log", log], harness().io)).toBe(1);
  expect(await run(["frobnicate"], harness().io)).toBe(2);
  expect(info.mnemonic).toBeTruthy();
  expect(d).toBeTruthy();
});

test("domain: name an apex (BYO domain) offline, emitting did.jsonl + the did:web did.json it derives, which verify", async () => {
  const { d, log, info, env } = await created();
  const moved = harness(env);
  expect(await run(["domain", "digitalcommons.jp", "--log", log, "--out", d, "--json"], moved.io)).toBe(0);
  const result = JSON.parse(moved.out);
  expect(result.did).toBe(info.did); // the DID does not change
  expect(result.didWeb).toBe("did:web:digitalcommons.jp");
  expect(result.locations).toEqual(["https://digitalcommons.jp"]);

  const didJson = JSON.parse(readFileSync(join(d, ".well-known", "did.json"), "utf8"));
  expect(didJson.id).toBe("did:web:digitalcommons.jp");
  expect(didJson.alsoKnownAs).toEqual([`${info.did}?src=https://digitalcommons.jp`]);
  expect(await run(["verify", join(d, ".well-known", "did.jsonl")], harness().io)).toBe(0);
  expect(await run(["domain", "not a host", "--log", log, "--out", d], harness(env).io)).not.toBe(0);
});

test("export: regenerates did.jsonl + did.json after an update, without a secret; before a location there is no did.json", async () => {
  const { d, log, env } = await created();
  const early = join(d, "early");
  const note = harness();
  expect(await run(["export", "--log", log, "--out", early], note.io)).toBe(0);
  expect(note.out).toMatch(/no location yet/);
  expect(() => readFileSync(join(early, ".well-known", "did.json"))).toThrow();

  await run(["domain", "digitalcommons.jp", "--log", log, "--out", d], harness(env).io);
  expect(await run(["service", "add", "#files", "relativeRef", "https://digitalcommons.jp/", "--log", log, "--local"], harness(env).io)).toBe(0);
  const out = join(d, "site");
  expect(await run(["export", "--log", log, "--out", out], harness().io)).toBe(0);
  const didJson = JSON.parse(readFileSync(join(out, ".well-known", "did.json"), "utf8"));
  expect(didJson.id).toBe("did:web:digitalcommons.jp");
  expect(didJson.service.some((s: any) => s.id === "#files")).toBe(true);
  expect(await run(["verify", join(out, ".well-known", "did.jsonl")], harness().io)).toBe(0);
});

test("new creates missing parent directories for --log", async () => {
  const log = join(dir(), "a", "b", "did.jsonl");
  expect(await run(["new", "--log", log, "--json"], harness().io)).toBe(0);
  expect(readFileSync(log, "utf8").length).toBeGreaterThan(0);
});

test("publish: PUTs the log to a third-party host at an apex domain, then re-publishes after an update", async () => {
  const { createByoHost } = await import("../server/host/byo-host.ts");
  const root = dir();
  const handler = createByoHost({ root, domain: "digitalcommons.example" });
  globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => handler(new Request(input, init))) as typeof fetch;
  const { d, log, env } = await created();
  await run(["domain", "digitalcommons.example", "--log", log, "--out", d], harness(env).io);

  const first = harness();
  expect(await run(["publish", "--log", log, "--json"], first.io)).toBe(0);
  const result = JSON.parse(first.out);
  expect(result.logUrl).toBe("https://digitalcommons.example/.well-known/did.jsonl");
  expect(result.verified).toBe(true);
  expect(readFileSync(join(root, ".well-known", "did.jsonl"), "utf8")).toBe(readFileSync(log, "utf8"));

  await run(["rotate", "--log", log, "--local"], harness(env).io);
  const second = harness();
  expect(await run(["publish", "--log", log, "--json"], second.io)).toBe(0);
  expect(JSON.parse(second.out).versionId.startsWith("3-")).toBe(true);
});

test("the state file follows $XDG_STATE_HOME, then $HOME/.local/state", async () => {
  const { versionMemoryPath } = await import("../packages/cli/src/version-memory.ts");
  expect(versionMemoryPath({ XDG_STATE_HOME: "/s", HOME: "/h" })).toBe("/s/dito/versions.json");
  expect(versionMemoryPath({ HOME: "/h" })).toBe("/h/.local/state/dito/versions.json");
});

test("a damaged memory file is an error, not an empty memory", async () => {
  const { log, info, env } = await created();
  await run(["connect", "alice", "--log", log], harness(env).io);
  const { mkdirSync, writeFileSync: write } = await import("node:fs");
  const state = dir();
  mkdirSync(join(state, "dito"));
  for (const damaged of ["{not json", "[]", JSON.stringify({ x: { versionNumber: "1" } })]) {
    write(join(state, "dito", "versions.json"), damaged);
    const failed = harness({ XDG_STATE_HOME: state });
    expect(await run(["verify", info.did, "--watcher", "https://anywhere.did.md"], failed.io)).toBe(1);
    expect(failed.err).toContain("--no-memory");
    expect(await run(["verify", info.did, "--watcher", "https://anywhere.did.md", "--no-memory"], harness({ XDG_STATE_HOME: state }).io)).toBe(0);
  }
});
