import { afterEach, beforeEach, expect, test } from "vitest";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run } from "../packages/cli/src/cli.ts";
import { createByoHost } from "../server/host/byo-host.ts";

// `dito publish` against the one-domain file host: what it writes is what a static server serves.
const realFetch = globalThis.fetch;
const root = () => mkdtempSync(join(tmpdir(), "byo-host-"));
let site: string;
beforeEach(() => {
  site = root();
  const host = createByoHost({ root: site, domain: "digitalcommons.example" });
  globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => host(new Request(input, init))) as typeof fetch;
});
afterEach(() => { globalThis.fetch = realFetch; });

function harness(env: Record<string, string | undefined> = {}) {
  let out = "";
  return { io: { out: (t: string) => { out += t; }, err: () => {}, env }, get out() { return out; } };
}

test("publish writes did.jsonl and its did:web mirror under ROOT/.well-known, and updates them", async () => {
  const log = join(root(), "did.jsonl");
  const made = harness();
  await run(["new", "--log", log, "--json"], made.io);
  const env = { DITO_MNEMONIC: JSON.parse(made.out).mnemonic };
  await run(["domain", "digitalcommons.example", "--log", log, "--out", root()], harness(env).io);

  expect(await run(["publish", "--log", log], harness().io)).toBe(0);
  const wellKnown = (name: string) => readFileSync(join(site, ".well-known", name), "utf8");
  expect(wellKnown("did.jsonl")).toBe(readFileSync(log, "utf8"));
  expect(JSON.parse(wellKnown("did.json")).id).toBe("did:web:digitalcommons.example");

  await run(["service", "add", "#files", "relativeRef", "https://digitalcommons.example/", "--log", log, "--local"], harness(env).io);
  expect(await run(["publish", "--log", log], harness().io)).toBe(0);
  expect(wellKnown("did.jsonl")).toBe(readFileSync(log, "utf8"));
  expect(JSON.parse(wellKnown("did.json")).service.some((s: any) => s.id === "#files")).toBe(true);
});

test("it serves its own domain only, one identity, and a stranger cannot replace it", async () => {
  const log = join(root(), "did.jsonl");
  const made = harness();
  await run(["new", "--log", log, "--json"], made.io);
  const env = { DITO_MNEMONIC: JSON.parse(made.out).mnemonic };

  await run(["domain", "elsewhere.example", "--log", log, "--out", root()], harness(env).io);
  expect(await run(["publish", "--log", log], harness().io)).not.toBe(0);
  expect(existsSync(join(site, ".well-known"))).toBe(false);

  const mine = join(root(), "did.jsonl");
  const first = harness();
  await run(["new", "--log", mine, "--json"], first.io);
  await run(["domain", "digitalcommons.example", "--log", mine, "--out", root()], harness({ DITO_MNEMONIC: JSON.parse(first.out).mnemonic }).io);
  expect(await run(["publish", "--log", mine], harness().io)).toBe(0);

  const stranger = join(root(), "did.jsonl");
  const other = harness();
  await run(["new", "--log", stranger, "--json"], other.io);
  await run(["domain", "digitalcommons.example", "--log", stranger, "--out", root()], harness({ DITO_MNEMONIC: JSON.parse(other.out).mnemonic }).io);
  expect(await run(["publish", "--log", stranger], harness().io)).not.toBe(0);
  expect(readFileSync(join(site, ".well-known/did.jsonl"), "utf8")).toBe(readFileSync(mine, "utf8"));
});
