import { expect, test } from "vitest";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run } from "../packages/cli/src/cli.ts";

function harness(env: Record<string, string | undefined> = {}) {
  let out = "", err = "";
  return { io: { out: (t: string) => { out += t; }, err: (t: string) => { err += t; }, env }, get out() { return out; }, get err() { return err; } };
}
const dir = () => mkdtempSync(join(tmpdir(), "dito-cli-"));

test("new -> show -> verify -> offline service/rotate, all from files, with --json for agents", async () => {
  const d = dir(), log = join(d, "did.jsonl");
  const made = harness();
  expect(await run(["new", "--log", log, "--json"], made.io)).toBe(0);
  const created = JSON.parse(made.out);
  expect(created.provisional).toBe(true);
  expect(created.mnemonic.split(" ")).toHaveLength(24);

  const shown = harness();
  expect(await run(["show", "--log", log, "--json"], shown.io)).toBe(0);
  expect(JSON.parse(shown.out).did).toBe(created.did);

  expect(await run(["verify", "--log", log], harness().io)).toBe(0);

  const env = { DITO_MNEMONIC: created.mnemonic };
  const added = harness(env);
  expect(await run(["service", "add", "#files", "relativeRef", "https://example.com/", "--log", log, "--json"], added.io)).toBe(0);
  expect(JSON.parse(added.out).entries).toBe(2);
  expect(await run(["rotate", "--log", log], harness(env).io)).toBe(0);

  const final = harness();
  await run(["show", "--log", log, "--json"], final.io);
  const doc = JSON.parse(final.out);
  expect(doc.entries).toBe(3);
  expect(doc.document.service.some((s: any) => s.id === "#files")).toBe(true);

  const removed = harness(env);
  expect(await run(["service", "remove", "#files", "--log", log], removed.io)).toBe(0);
});

test("failure modes: refuses to overwrite, wrong mnemonic, tampered log, missing secrets, unknown command", async () => {
  const d = dir(), log = join(d, "did.jsonl");
  const made = harness();
  await run(["new", "--log", log, "--json"], made.io);
  const mnemonic = JSON.parse(made.out).mnemonic;

  expect(await run(["new", "--log", log], harness().io)).toBe(2);
  expect(await run(["rotate", "--log", log], harness().io)).toBe(2); // no mnemonic anywhere
  const other = harness(); await run(["new", "--log", join(d, "other.jsonl"), "--json"], other.io);
  const wrong = harness({ DITO_MNEMONIC: JSON.parse(other.out).mnemonic });
  expect(await run(["rotate", "--log", log], wrong.io)).toBe(1);
  expect(wrong.err).toMatch(/Root Key/);

  const tampered = readFileSync(log, "utf8").replace("SelfIssuedOPAuthorizationEndpoint", "Evil");
  writeFileSync(log, tampered.replace("\"service\":[]", "\"service\":[{\"id\":\"#x\",\"type\":\"X\",\"serviceEndpoint\":\"https://evil\"}]"));
  writeFileSync(log, readFileSync(log, "utf8").replace("\"authentication\"", "\"name\":\"tampered\",\"authentication\""));
  expect(await run(["verify", "--log", log], harness().io)).toBe(1);
  expect(await run(["frobnicate"], harness().io)).toBe(2);
  expect(mnemonic).toBeTruthy();
});

test("domain: re-home on an apex (BYO domain) offline, emitting did.jsonl + did:web did.json that verify", async () => {
  const d = dir(), log = join(d, "did.jsonl");
  const made = harness();
  await run(["new", "--log", log, "--json"], made.io);
  const env = { DITO_MNEMONIC: JSON.parse(made.out).mnemonic };

  const moved = harness(env);
  expect(await run(["domain", "digitalcommons.jp", "--log", log, "--out", d, "--json"], moved.io)).toBe(0);
  const result = JSON.parse(moved.out);
  expect(result.did.endsWith(":digitalcommons.jp")).toBe(true);
  expect(result.didWeb).toBe("did:web:digitalcommons.jp");

  const didJson = JSON.parse(readFileSync(join(d, ".well-known", "did.json"), "utf8"));
  expect(didJson.id).toBe("did:web:digitalcommons.jp");
  expect(await run(["verify", join(d, ".well-known", "did.jsonl")], harness().io)).toBe(0);

  expect(await run(["domain", "not a host", "--log", log, "--out", d], harness(env).io)).not.toBe(0);
});

test("export: regenerates did.jsonl + did.json after an update, without a secret", async () => {
  const d = dir(), log = join(d, "did.jsonl");
  const made = harness();
  await run(["new", "--log", log, "--json"], made.io);
  const env = { DITO_MNEMONIC: JSON.parse(made.out).mnemonic };
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

test("export --jwe / import: <scid>.jwe + mnemonic restores an apex (username-less) identity", async () => {
  const d = dir(), log = join(d, "did.jsonl");
  const made = harness();
  await run(["new", "--log", log, "--json"], made.io);
  const mnemonic = JSON.parse(made.out).mnemonic;
  const env = { DITO_MNEMONIC: mnemonic };
  await run(["domain", "digitalcommons.jp", "--log", log, "--out", d], harness(env).io);

  const exported = harness(env);
  expect(await run(["export", "--jwe", "--log", log, "--out", d, "--json"], exported.io)).toBe(0);
  const { scid, wrote } = JSON.parse(exported.out);
  expect(wrote.endsWith(`${scid}.jwe`)).toBe(true);
  expect(readFileSync(wrote, "utf8").split(".")).toHaveLength(5);

  const restored = join(d, "restored", "did.jsonl");
  const imported = harness(env);
  expect(await run(["import", wrote, "--log", restored, "--json"], imported.io)).toBe(0);
  expect(JSON.parse(imported.out).did.endsWith(":digitalcommons.jp")).toBe(true);
  expect(readFileSync(restored, "utf8")).toBe(readFileSync(log, "utf8"));

  const other = harness();
  await run(["new", "--log", join(d, "x.jsonl"), "--json"], other.io);
  expect(await run(["import", wrote, "--log", join(d, "y.jsonl")], harness({ DITO_MNEMONIC: JSON.parse(other.out).mnemonic }).io)).not.toBe(0);
});

test("publish: PUTs the log to a third-party host at an apex domain, then re-publishes after an update", async () => {
  const { createReferenceHost } = await import("../packages/webvh/src/index.ts");
  const handler = createReferenceHost();
  const realFetch = globalThis.fetch;
  globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => handler(new Request(input, init))) as typeof fetch;
  try {
    const d = dir(), log = join(d, "did.jsonl");
    const made = harness();
    await run(["new", "--log", log, "--json"], made.io);
    const env = { DITO_MNEMONIC: JSON.parse(made.out).mnemonic };
    await run(["domain", "digitalcommons.example", "--log", log, "--out", d], harness(env).io);

    const first = harness();
    expect(await run(["publish", "--log", log, "--json"], first.io)).toBe(0);
    const result = JSON.parse(first.out);
    expect(result.logUrl).toBe("https://digitalcommons.example/.well-known/did.jsonl");
    expect(result.verified).toBe(true);

    await run(["rotate", "--log", log, "--local"], harness(env).io);
    const second = harness();
    expect(await run(["publish", "--log", log, "--json"], second.io)).toBe(0);
    expect(JSON.parse(second.out).versionId.startsWith("3-")).toBe(true);
  } finally { globalThis.fetch = realFetch; }
});

// ---- the version memory (verify/fetch <did>, forget) ----------------------------------------------------------------

async function servedHistory() {
  const { Ed25519Signer, createLog, keyFromPrivateKey, nextKeyHash, serializeLog, updateLog } = await import("../packages/webvh/src/index.ts");
  const keys = [keyFromPrivateKey(crypto.getRandomValues(new Uint8Array(32))), keyFromPrivateKey(crypto.getRandomValues(new Uint8Array(32))), keyFromPrivateKey(crypto.getRandomValues(new Uint8Array(32))), keyFromPrivateKey(crypto.getRandomValues(new Uint8Array(32)))];
  const created = await createLog({ domain: "example.com", signer: new Ed25519Signer(keys[0]!), updateKeys: [keys[0]!.multikey], nextKeyHashes: [await nextKeyHash(keys[1]!.multikey)], verificationMethods: [{ id: "#k", type: "Multikey", publicKeyMultibase: keys[0]!.multikey }], authentication: ["#k"] });
  const second = await updateLog({ log: created.log, signer: new Ed25519Signer(keys[1]!), updateKeys: [keys[1]!.multikey], nextKeyHashes: [await nextKeyHash(keys[2]!.multikey)] });
  const forkOfSecond = await updateLog({ log: created.log, signer: new Ed25519Signer(keys[1]!), updateKeys: [keys[1]!.multikey], nextKeyHashes: [await nextKeyHash(keys[3]!.multikey)] });
  return { did: created.did, one: serializeLog(created.log), two: serializeLog(second.log), fork: serializeLog(forkOfSecond.log) };
}

async function serving(body: () => string, task: () => Promise<void>) {
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL) => String(input).startsWith("https://example.com/.well-known/did.jsonl") ? new Response(body()) : new Response("", { status: 404 })) as typeof fetch;
  try { await task(); } finally { globalThis.fetch = realFetch; }
}

test("verify <did> remembers the newest version it saw, refuses an older or forked copy, and forget / --no-memory are the ways out", async () => {
  const h = await servedHistory();
  const state = dir();
  const env = { XDG_STATE_HOME: state };
  let serve = h.two;
  await serving(() => serve, async () => {
    expect(await run(["verify", h.did], harness(env).io)).toBe(0);
    expect(JSON.parse(readFileSync(join(state, "dito", "versions.json"), "utf8"))[`did:webvh:${h.did.split(":")[2]}`].versionId.startsWith("2-")).toBe(true);

    // The host now serves the first version only: it verifies on its own, but this is older than what was seen.
    serve = h.one;
    const old = harness(env);
    expect(await run(["verify", h.did], old.io)).toBe(1);
    expect(old.err).toMatch(/older/);
    expect(old.err).toContain(`dito forget ${h.did}`);
    expect(await run(["verify", h.did, "--no-memory"], harness(env).io)).toBe(0);

    // A different second version: the other half of a fork.
    serve = h.fork;
    const forked = harness(env);
    expect(await run(["verify", h.did], forked.io)).toBe(1);
    expect(forked.err).toMatch(/forks/);

    // Forgetting lets any valid log through, and the memory starts again from it.
    const forgot = harness(env);
    expect(await run(["forget", h.did, "--json"], forgot.io)).toBe(0);
    expect(JSON.parse(forgot.out).forgotten).toBe(true);
    expect(await run(["verify", h.did], harness(env).io)).toBe(0);
    expect(await run(["forget", h.did, "--json"], harness(env).io)).toBe(0);
    const nothing = harness(env);
    await run(["forget", h.did, "--json"], nothing.io);
    expect(JSON.parse(nothing.out).forgotten).toBe(false);
  });
});

test("fetch <did> uses the memory too, and --no-memory touches no file", async () => {
  const h = await servedHistory();
  const state = dir(), d = dir();
  const env = { XDG_STATE_HOME: state };
  await serving(() => h.one, async () => {
    expect(await run(["fetch", h.did, "--log", join(d, "a.jsonl"), "--no-memory"], harness(env).io)).toBe(0);
    expect(() => readFileSync(join(state, "dito", "versions.json"), "utf8")).toThrow();
    expect(await run(["fetch", h.did, "--log", join(d, "b.jsonl")], harness(env).io)).toBe(0);
    expect(readFileSync(join(state, "dito", "versions.json"), "utf8")).toContain("1-");
  });
  await serving(() => h.two, async () => { expect(await run(["verify", h.did], harness(env).io)).toBe(0); });
  await serving(() => h.one, async () => { expect(await run(["fetch", h.did, "--log", join(d, "c.jsonl")], harness(env).io)).toBe(1); });
});

test("a damaged memory file is an error, not an empty memory", async () => {
  const h = await servedHistory();
  const state = dir();
  const { mkdirSync } = await import("node:fs");
  mkdirSync(join(state, "dito"));
  for (const damaged of ["{not json", "[]", JSON.stringify({ x: { versionNumber: "1" } })]) {
    writeFileSync(join(state, "dito", "versions.json"), damaged);
    const failed = harness({ XDG_STATE_HOME: state });
    await serving(() => h.two, async () => { expect(await run(["verify", h.did], failed.io)).toBe(1); });
    expect(failed.err).toContain("--no-memory");
    await serving(() => h.two, async () => { expect(await run(["verify", h.did, "--no-memory"], harness({ XDG_STATE_HOME: state }).io)).toBe(0); });
  }
});

test("the state file follows $XDG_STATE_HOME, then $HOME/.local/state", async () => {
  const { versionMemoryPath } = await import("../packages/cli/src/version-memory.ts");
  expect(versionMemoryPath({ XDG_STATE_HOME: "/s", HOME: "/h" })).toBe("/s/dito/versions.json");
  expect(versionMemoryPath({ HOME: "/h" })).toBe("/h/.local/state/dito/versions.json");
});
