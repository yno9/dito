import { expect, test } from "bun:test";
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

  const tampered = readFileSync(log, "utf8").replace("UDIWalletIssuer", "Evil");
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
