import { afterEach, beforeEach, expect, test } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { formatReport, runVhConformance } from "../packages/vh/src/index.ts";
import { Identity } from "../packages/wallet/src/identity.ts";
import { createByoHost } from "../server/host/byo-host.ts";

// The protocol must not depend on did.md's server. Here a second, independent implementation (server/host/byo-host.ts:
// one domain, one identity, plain files) plays a third-party server on non-did.md domains.
const realFetch = globalThis.fetch;
const dir = () => mkdtempSync(join(tmpdir(), "third-party-"));
const handlers = new Map<string, (request: Request) => Promise<Response>>();
beforeEach(() => {
  handlers.clear();
  for (const domain of ["alice.example.org", "alice.example.net", ...Array.from({ length: 40 }, (_, index) => `conf${index}.example.org`)]) handlers.set(domain, createByoHost({ root: dir(), domain }));
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input, init);
    const handler = handlers.get(new URL(request.url).hostname);
    return handler ? handler(request) : new Response("no such host", { status: 404 });
  }) as typeof fetch;
});
afterEach(() => { globalThis.fetch = realFetch; });

test("dito's wallet hosts an identity on a third-party server: connect, update, rotate, a second device, move, unpublish", async () => {
  const { identity, mnemonic } = await Identity.create();
  const result = await identity.connect({ username: "alice", domain: "example.org" });
  expect(result.logUrl).toBe("https://alice.example.org/.well-known/did.jsonl");
  expect(result.verifiedLive).toBe(true);
  await identity.publishUpdate(state => ({ ...state, service: [{ id: "#x", type: "X", serviceEndpoint: "https://alice.example.org/" }] }));
  await identity.rotate();

  const other = await Identity.fromSource({ mnemonic, src: "https://alice.example.org" }); // a second device, reading from the third-party host
  expect(other.entries).toHaveLength(identity.entries.length);
  expect(other.did).toBe(identity.did);
  const didWeb = await (await fetch("https://alice.example.org/.well-known/did.json")).json();
  expect(didWeb.id).toBe("did:web:alice.example.org");
  expect(didWeb.alsoKnownAs).toEqual([`${identity.did}?src=https://alice.example.org`]);

  // move to a different third-party domain; the DID stays and the old copy is removed
  const moved = await identity.connect({ username: "alice", domain: "example.net" });
  expect(moved.cleanupError).toBeUndefined();
  expect((await fetch("https://alice.example.org/.well-known/did.jsonl")).status).toBe(404);
  const again = await Identity.fromSource({ mnemonic, src: "https://alice.example.net" });
  expect(again.did).toBe(identity.did);
  expect(again.locations.map(location => location.src)).toEqual(["https://alice.example.net"]);

  await identity.unpublish();
  expect((await fetch("https://alice.example.net/.well-known/did.jsonl")).status).toBe(404);
});

test("a third-party host that serves one domain refuses a log for another, and the wallet shows why", async () => {
  const { identity } = await Identity.create();
  handlers.set("other.example.org", createByoHost({ root: dir(), domain: "elsewhere.example.org" }));
  await expect(identity.connect({ username: "other", domain: "example.org" })).rejects.toThrow(/serves elsewhere\.example\.org only/);
  expect(identity.isProvisional).toBe(true); // local state untouched
});

test("a third-party host passes the shared core of the conformance suite for the single identity it keeps", async () => {
  // byo-host keeps one identity per domain and no SCID index, so the checks about watchers and moves between names
  // (V3, V7, V9) do not apply to it; what must hold is the shared core: publish, derive did.json, append, refuse, take down.
  let counter = 0;
  const results = await runVhConformance({ newLocation: () => `conf${counter++}.example.org`, fetch: globalThis.fetch });
  const core = results.filter(result => /^V(0|1|2|4|5|6|8|10|11)\./.test(result.name));
  expect(core.length).toBeGreaterThanOrEqual(8);
  const failed = core.filter(result => !result.ok && !result.optional);
  if (failed.length) console.log(formatReport(core).text);
  expect(failed.map(result => result.name)).toEqual([]);
});
