import { afterEach, beforeEach, expect, test } from "bun:test";
import { Identity } from "../packages/wallet/src/identity.ts";
import { validateLogAt } from "../packages/wallet/src/webvh-core.ts";

// --- a tiny did.md stand-in: validates every write like the real host does
type Call = { method: string; url: string };
let calls: Call[] = [];
let store = new Map<string, string>();
const realFetch = globalThis.fetch;

beforeEach(() => {
  calls = []; store = new Map();
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input).replace(/[?&]_=\d+$/, "");
    const method = (init?.method ?? "GET").toUpperCase();
    calls.push({ method, url });
    const host = new URL(url).host;
    if (method === "GET") return store.has(host) ? new Response(store.get(host)) : new Response("nope", { status: 404 });
    if (method === "DELETE") { store.delete(host); return new Response("ok"); }
    let text = String(init?.body);
    if (method === "POST") text = (store.get(host) ?? "") + text;
    const entries = text.trimEnd().split("\n").map(line => JSON.parse(line));
    try { await validateLogAt(entries, [], `https://${host}/.well-known/did.jsonl`); }
    catch (error) { return new Response(String((error as Error).message), { status: 400 }); }
    store.set(host, text);
    return new Response("ok");
  }) as typeof fetch;
});
afterEach(() => { globalThis.fetch = realFetch; });

test("create -> open round-trips through the log text and mnemonic alone", async () => {
  const { identity, mnemonic } = await Identity.create({ api: "https://api.did.md" });
  expect(identity.isProvisional).toBe(true);
  expect(mnemonic.split(" ")).toHaveLength(24);
  const reopened = await Identity.open({ mnemonic, log: identity.logText() });
  expect(reopened.did).toBe(identity.did);
  expect(reopened.state.service[0].type).toBe("UDIWalletIssuer");
});

test("open rejects a wrong mnemonic and a tampered log", async () => {
  const { identity } = await Identity.create();
  const other = await Identity.create();
  await expect(Identity.open({ mnemonic: other.mnemonic, log: identity.logText() })).rejects.toThrow(/Root Key/);
  const entries = JSON.parse(JSON.stringify(identity.entries));
  entries[0].state.name = "tampered";
  await expect(Identity.open({ mnemonic: (await Identity.create()).mnemonic, log: entries })).rejects.toThrow();
  await expect(Identity.open({ mnemonic: identity.mnemonic, log: entries })).rejects.toThrow();
});

test("offline: move to a host, edit the document, rotate -- and reopen from the log each time", async () => {
  const { identity, mnemonic } = await Identity.create();
  const scid = identity.scid;
  await identity.commit(await identity.prepareMove({ username: "alice", domain: "did.md" }));
  expect(identity.did).toBe(`did:webvh:${scid}:alice.did.md`);
  expect(identity.isProvisional).toBe(false);

  const step = await identity.prepareUpdate({ ...identity.state, service: [...(identity.state.service ?? []), { id: "#files", type: "relativeRef", serviceEndpoint: "https://alice.did.md/" }] });
  await identity.commit(step);
  await identity.commit(await identity.prepareUpdate(identity.state));

  expect(identity.entries).toHaveLength(4);
  const reopened = await Identity.open({ mnemonic, log: identity.logText() });
  expect(reopened.state.service.some((service: any) => service.id === "#files")).toBe(true);
  expect(reopened.entries).toHaveLength(4);
});

test("connect -> publishUpdate -> rotate -> unpublish drive the did.md host", async () => {
  const { identity } = await Identity.create();
  const result = await identity.connect({ username: "bob" });
  expect(result.logUrl).toBe("https://bob.did.md/.well-known/did.jsonl");
  expect(store.get("bob.did.md")!.trim().split("\n")).toHaveLength(2);
  expect(await identity.isLive()).toBe(true);

  await identity.publishUpdate(state => ({ ...state, service: [{ id: "#x", type: "X", serviceEndpoint: "https://bob.example/" }] }));
  await identity.rotate();
  expect(store.get("bob.did.md")!.trim().split("\n")).toHaveLength(4);
  expect(calls.filter(call => call.method === "POST")).toHaveLength(2);

  await identity.unpublish();
  expect(store.has("bob.did.md")).toBe(false);
  expect(await identity.isLive()).toBe(false);
});

test("a rejected publish leaves local state untouched", async () => {
  const { identity } = await Identity.create();
  await identity.connect({ username: "carol" });
  const before = identity.entries.length;
  store.delete("carol.did.md"); // host lost the log: an append can no longer chain
  await expect(identity.rotate()).rejects.toThrow();
  expect(identity.entries).toHaveLength(before);
});

import { mkdtempSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run } from "../packages/cli/src/cli.ts";

test("Identity.fromDid opens an identity on a fresh device from its published log; CLI fetch/verify do the same", async () => {
  const { identity, mnemonic } = await Identity.create();
  await identity.connect({ username: "dana" });
  await identity.rotate();

  const device2 = await Identity.fromDid({ did: identity.did, mnemonic });
  expect(device2.did).toBe(identity.did);
  expect(device2.entries).toHaveLength(identity.entries.length);
  await device2.rotate(); // the second device can act, too

  let out = "", err = "";
  const io = { out: (t: string) => { out += t; }, err: (t: string) => { err += t; }, env: {} };
  const logFile = join(mkdtempSync(join(tmpdir(), "dito-fetch-")), "did.jsonl");
  expect(await run(["fetch", identity.did, "--log", logFile, "--json"], io)).toBe(0);
  expect(existsSync(logFile)).toBe(true);
  expect(readFileSync(logFile, "utf8").trim().split("\n")).toHaveLength(device2.entries.length);
  expect(await run(["verify", identity.did, "--json"], io)).toBe(0);
  expect(err).toBe("");
  await expect(Identity.fromDid({ did: identity.did, mnemonic: (await Identity.create()).mnemonic })).rejects.toThrow(/Root Key/);
});
