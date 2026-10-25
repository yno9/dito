import { expect, test } from "vitest";
import { createVhLog, keyFromPrivateKey, serializeVhLog, updateVhLog, type VhLogEntry } from "../packages/vh/src/index.ts";
import { MemoryWatcherStore, createWatcher, hostAllowed } from "../packages/watcher/src/index.ts";
import { SqliteWatcherStore } from "../packages/watcher/src/sqlite-store.ts";

const key = () => keyFromPrivateKey(crypto.getRandomValues(new Uint8Array(32)));

async function identity(host = "alice.did.md") {
  const k0 = key();
  const created = await createVhLog({
    signer: k0, updateKeys: [k0.multikey],
    document: did => ({
      "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"], id: did, alsoKnownAs: [`did:web:${host}`],
      verificationMethod: [{ id: `${did}#k`, type: "Multikey", controller: did, publicKeyMultibase: k0.multikey }], authentication: [`${did}#k`],
    }),
  });
  const extend = (log: VhLogEntry[], name: string) => updateVhLog({ log, signer: k0, now: Date.now() + 5000 * log.length, document: { ...log.at(-1)!.state, name } });
  return { ...created, k0, extend };
}

/** The web as the watcher sees it: the log at each location is whatever the test last put there. */
function web() {
  const logs = new Map<string, VhLogEntry[]>();
  const asked: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL) => {
    const url = String(input);
    asked.push(url);
    const host = new URL(url).host;
    const log = logs.get(host);
    return log ? new Response(serializeVhLog(log)) : new Response("not found", { status: 404 });
  }) as typeof fetch;
  return { logs, asked, fetchImpl };
}

function setup(allow = { hosts: ["*.did.md"] }) {
  const world = web();
  const store = new MemoryWatcherStore();
  const watcher = createWatcher({ store, allow, fetch: world.fetchImpl, adminToken: "secret" });
  const call = (path: string, init?: RequestInit) => watcher.handle(new Request(`https://watcher.test${path}`, init));
  const notify = (did: string, src?: string) => call(`/log?id=${encodeURIComponent(src ? `${did}?src=${src}` : did)}`, { method: "POST" });
  return { world, store, call, notify };
}

test("a notification makes the watcher fetch, verify and hold the log; GET /log?scid= serves it", async () => {
  const { world, call, notify } = setup();
  const alice = await identity();
  world.logs.set("alice.did.md", alice.log);
  const scid = alice.did.slice("did:vh:".length);
  expect((await call(`/log?scid=${scid}`)).status).toBe(404);
  const stored = await notify(alice.did, "https://alice.did.md");
  expect(await stored.json()).toEqual({ did: alice.did, status: "stored", versionNumber: 1 });
  expect(world.asked).toEqual(["https://alice.did.md/.well-known/did.jsonl"]);
  const served = await call(`/log?scid=${scid}`);
  expect(served.status).toBe(200);
  expect(served.headers.get("access-control-allow-origin")).toBe("*");
  expect(await served.text()).toBe(serializeVhLog(alice.log));
});

test("a later notification extends the log, an old one changes nothing, and one without a src follows the last place", async () => {
  const { world, call, notify } = setup();
  const alice = await identity();
  world.logs.set("alice.did.md", alice.log);
  await notify(alice.did, "https://alice.did.md");
  const longer = (await alice.extend(alice.log, "Alice")).log;
  world.logs.set("alice.did.md", longer);
  expect(await (await notify(alice.did)).json()).toMatchObject({ status: "updated", versionNumber: 2 });
  expect(await (await notify(alice.did)).json()).toMatchObject({ status: "unchanged", versionNumber: 2 });
  world.logs.set("alice.did.md", alice.log);
  expect(await (await notify(alice.did)).json()).toMatchObject({ status: "stale", versionNumber: 2 });
  expect(await (await call(`/log?scid=${alice.did.slice(7)}`)).text()).toBe(serializeVhLog(longer));
});

test("two continuations of one history: the first is kept, the second is recorded as a fork and refused with 409", async () => {
  const { world, call, notify } = setup();
  const alice = await identity();
  world.logs.set("alice.did.md", alice.log);
  await notify(alice.did, "https://alice.did.md");
  const a = (await alice.extend(alice.log, "A")).log;
  const b = (await alice.extend(alice.log, "B")).log;
  world.logs.set("alice.did.md", a);
  expect((await notify(alice.did)).status).toBe(200);
  world.logs.set("alice.did.md", b);
  const forked = await notify(alice.did);
  expect(forked.status).toBe(409);
  expect(await forked.json()).toMatchObject({ status: "forked", versionNumber: 2, held: a[1]!.versionId, seen: b[1]!.versionId });
  const served = await call(`/log?scid=${alice.did.slice(7)}`);
  expect(await served.text()).toBe(serializeVhLog(a));
  expect(served.headers.get("x-did-vh-forks")).toBe("1");
});

test("a log that does not verify, or is another identity's, is not held", async () => {
  const { world, notify, call } = setup();
  const alice = await identity();
  const mallory = await identity();
  const tampered = structuredClone(alice.log);
  (tampered[0]!.state as { name?: string }).name = "forged";
  world.logs.set("alice.did.md", tampered);
  expect((await notify(alice.did, "https://alice.did.md")).status).toBe(422);
  world.logs.set("alice.did.md", mallory.log);
  expect((await notify(alice.did, "https://alice.did.md")).status).toBe(422);
  expect((await call(`/log?scid=${alice.did.slice(7)}`)).status).toBe(404);
  world.logs.delete("alice.did.md");
  expect((await notify(alice.did, "https://alice.did.md")).status).toBe(404);
});

test("only identities the operator listed are fetched; nothing is fetched for any other", async () => {
  const { world, notify } = setup({ hosts: ["*.did.md"] });
  const eve = await identity("eve.example.org");
  world.logs.set("eve.example.org", eve.log);
  expect((await notify(eve.did, "https://eve.example.org")).status).toBe(403);
  expect((await notify(eve.did, "https://evil-did.md")).status).toBe(403);
  expect(world.asked).toEqual([]);
  const none = setup({ hosts: [] });
  expect((await none.notify(eve.did, "https://alice.did.md")).status).toBe(403);
  const byScid = setup({ hosts: [], scids: [eve.did.slice(7)] } as never);
  byScid.world.logs.set("eve.example.org", eve.log);
  expect((await byScid.notify(eve.did, "https://eve.example.org")).status).toBe(200);
  expect(hostAllowed("alice.did.md", ["*.did.md"])).toBe(true);
  expect(hostAllowed("did.md", ["*.did.md"])).toBe(false);
  expect(hostAllowed("alice.did.md", ["alice.did.md"])).toBe(true);
});

test("a notification that names no place, for a log the watcher has never held, is asked to say where", async () => {
  const { notify } = setup();
  const alice = await identity();
  expect((await notify(alice.did)).status).toBe(400);
  expect((await notify("did:vh:short")).status).toBe(400);
});

test("only the operator's token deletes; witness files and resources are not supported", async () => {
  const { world, call, notify } = setup();
  const alice = await identity();
  world.logs.set("alice.did.md", alice.log);
  await notify(alice.did, "https://alice.did.md");
  const scid = alice.did.slice(7);
  expect((await call(`/log/delete?scid=${scid}`, { method: "POST" })).status).toBe(403);
  expect((await call(`/log/delete?scid=${scid}`, { method: "POST", headers: { authorization: "Bearer wrong" } })).status).toBe(403);
  expect((await call(`/log/delete?scid=${scid}`, { method: "POST", headers: { authorization: "Bearer secret" } })).status).toBe(200);
  expect((await call(`/log?scid=${scid}`)).status).toBe(404);
  expect((await call(`/witness?scid=${scid}`)).status).toBe(501);
  expect((await call(`/resource?scid=${scid}&path=x`)).status).toBe(501);
  expect((await call("/log", { method: "OPTIONS" })).status).toBe(204);
});

test("the SQLite store holds what the watcher puts in it, forks included, across a reopen", async () => {
  const { mkdtempSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const file = join(mkdtempSync(join(tmpdir(), "watcher-")), "watcher.sqlite");
  const first = new SqliteWatcherStore(file);
  const record = { scid: "Q".repeat(46), did: `did:vh:${"Q".repeat(46)}`, text: "{}\n", versionIds: ["1-a", "2-b"], source: "https://alice.did.md", forks: [{ versionNumber: 2, versionId: "2-c", seenAt: "2026-10-25T00:00:00.000Z", source: "https://alice.did.md" }], updatedAt: "2026-10-25T00:00:00.000Z" };
  await first.put(record);
  first.close();
  const second = new SqliteWatcherStore(file);
  expect(await second.get(record.scid)).toEqual(record);
  expect(await second.delete(record.scid)).toBe(true);
  expect(await second.get(record.scid)).toBeNull();
  second.close();
});
