import { afterEach, beforeEach, expect, test } from "bun:test";
import { createReferenceHost, formatReport, runConformance } from "../packages/webvh/src/index.ts";
import { Identity } from "../packages/wallet/src/identity.ts";

// The protocol must not depend on did.md's server. Here a second, independent
// implementation (packages/webvh's reference host, ~120 lines on didwebvh-ts) plays a
// third-party server on a non-did.md domain.
const realFetch = globalThis.fetch;
let handler: (request: Request) => Promise<Response>;
beforeEach(() => {
  handler = createReferenceHost();
  globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => handler(new Request(input, init))) as typeof fetch;
});
afterEach(() => { globalThis.fetch = realFetch; });

test("the reference host (an independent server) passes the same conformance suite as did.md's", async () => {
  let counter = 0;
  const results = await runConformance({ newLocation: () => `conf${counter++}.example.org`, fetch: globalThis.fetch });
  const report = formatReport(results);
  if (!report.ok) console.log(report.text);
  expect(report.ok).toBe(true);
});

test("dito's wallet, unchanged, hosts an identity on a third-party server: connect, update, rotate, move, unpublish", async () => {
  const { identity, mnemonic } = await Identity.create();
  const result = await identity.connect({ username: "alice", domain: "example.org" });
  expect(result.logUrl).toBe("https://alice.example.org/.well-known/did.jsonl");
  await identity.publishUpdate(state => ({ ...state, service: [{ id: "#x", type: "X", serviceEndpoint: "https://alice.example.org/" }] }));
  await identity.rotate();

  const other = await Identity.fromDid({ did: identity.did, mnemonic }); // a second device, reading from the third-party host
  expect(other.entries).toHaveLength(identity.entries.length);

  // move to a different third-party domain; the old copy is removed
  const moved = await identity.connect({ username: "alice", domain: "example.net" });
  expect(moved.cleanupError).toBeUndefined();
  expect(await (await fetch("https://alice.example.org/.well-known/did.jsonl")).status).toBe(404);
  expect((await Identity.fromDid({ did: identity.did, mnemonic })).did.endsWith(":alice.example.net")).toBe(true);

  await identity.unpublish();
  expect((await fetch("https://alice.example.net/.well-known/did.jsonl")).status).toBe(404);
});

test("a third-party host's policy refusal (403) reaches the wallet as a clear error", async () => {
  handler = createReferenceHost({ refuse: host => host.startsWith("reserved.") ? "name is reserved" : undefined });
  const { identity } = await Identity.create();
  await expect(identity.connect({ username: "reserved", domain: "example.org" })).rejects.toThrow(/name is reserved/);
  expect(identity.isProvisional).toBe(true); // local state untouched
});
