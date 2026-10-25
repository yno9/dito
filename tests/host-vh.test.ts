// did.md's host publishing did:vh logs: validation (the location rule), the derived did:web document,
// the SCID index and `GET /log?scid=`, deactivation and taking down. Driven through identityFetch with a
// swapped-in in-memory store, as identity-store.test.ts does.
import { afterEach, expect, test } from "vitest";
import { createDataIntegrityProof, keyFromPrivateKey } from "../packages/webvh/src/index.ts";
import {
  checkDidWebShadow, createVhLog, deactivateVhLog, keyHash, serializeVhLog, updateVhLog, type VhLogEntry,
} from "../packages/vh/src/index.ts";
import { identityFetch, setIdentityStore, type IdentitySlot, type IdentityStore } from "../server/host/identity-host.ts";

process.env.DATA_DIR = "/nonexistent/host-vh-test";

class MemoryStore implements IdentityStore {
  files = new Map<string, string>();
  private locks = new Map<string, Promise<void>>();
  index = new Map<string, string>();
  scids = {
    get: async (scid: string) => this.index.get(scid) ?? null,
    put: async (scid: string, username: string) => { this.index.set(scid, username); },
    remove: async (scid: string) => { this.index.delete(scid); },
  };
  async read(username: string, slot: IdentitySlot) { return this.files.get(`${username}/${slot}`) ?? null; }
  async write(username: string, slot: IdentitySlot, content: string) { this.files.set(`${username}/${slot}`, content); }
  async remove(username: string, slot: IdentitySlot) { this.files.delete(`${username}/${slot}`); }
  async exclusive<T>(name: string, task: () => Promise<T>): Promise<T> {
    const before = this.locks.get(name) ?? Promise.resolve();
    let release!: () => void;
    const after = new Promise<void>(resolve => { release = resolve; });
    this.locks.set(name, before.then(() => after));
    await before;
    try { return await task(); } finally { release(); if (this.locks.get(name) === after) this.locks.delete(name); }
  }
}

let store: MemoryStore;
afterEach(() => { setIdentityStore(new MemoryStore()); });
function fresh() { store = new MemoryStore(); setIdentityStore(store); return store; }

const key = () => keyFromPrivateKey(crypto.getRandomValues(new Uint8Array(32)));
const call = (name: string, path: string, init: RequestInit = {}) => {
  const url = new URL(`https://${name}.did.md${path}`);
  return identityFetch(new Request(url, { ...init, headers: { host: url.host, ...(init.headers as object) } }), url) as Promise<Response>;
};
const put = (name: string, log: VhLogEntry[]) => call(name, "/.well-known/did.jsonl", { method: "PUT", body: serializeVhLog(log) });
const post = (name: string, entries: VhLogEntry[]) => call(name, "/.well-known/did.jsonl", { method: "POST", body: serializeVhLog(entries) });

/** A did:vh identity that names `alice.did.md` (or another name) and has a service. */
async function identity(name = "alice") {
  const [k0, k1, k2] = [key(), key(), key()];
  const created = await createVhLog({
    signer: k0, updateKeys: [k0.multikey], nextKeyHashes: [keyHash(k1.multikey)],
    document: did => ({
      "@context": ["https://www.w3.org/ns/did/v1"], id: did, alsoKnownAs: [`did:web:${name}.did.md`],
      verificationMethod: [{ id: `${did}#k`, type: "Multikey", controller: did, publicKeyMultibase: k0.multikey }], authentication: [`${did}#k`],
    }),
  });
  return { ...created, k0, k1, k2, name };
}

test("a did:vh log naming this location is published, and its did:web document is the derivation, not the log", async () => {
  fresh();
  const { did, log } = await identity();
  expect((await put("alice", log)).status).toBe(201);

  const served = await call("alice", "/.well-known/did.jsonl");
  expect(served.status).toBe(200);
  expect(await served.text()).toBe(serializeVhLog(log));

  const web = await call("alice", "/.well-known/did.json");
  expect(web.status).toBe(200);
  const document = await web.json();
  expect(document.id).toBe("did:web:alice.did.md");
  expect(document.alsoKnownAs).toEqual([did]);
  expect(checkDidWebShadow(log[0]!.state, "did:web:alice.did.md", document)).toEqual({ ok: true });
  // The atproto handle file is the did:web DID, as for a did:webvh identity.
  expect((await (await call("alice", "/.well-known/atproto-did")).text()).trim()).toBe("did:web:alice.did.md");
});

test("a log that does not name this location is refused: the name must mean something", async () => {
  fresh();
  const { log } = await identity("alice");
  const response = await put("bob", log);
  expect(response.status).toBe(400);
  expect(await response.text()).toMatch(/must name did:web:bob\.did\.md/);
  expect(store.files.size).toBe(0);
  expect(store.index.size).toBe(0);
});

test("an update appended with POST regenerates the did:web document; PUT of the whole log also works", async () => {
  fresh();
  const { did, log, k1, k2 } = await identity();
  await put("alice", log);
  const next = await updateVhLog({
    log, signer: k1, now: Date.now() + 2000,
    document: { ...log[0]!.state, service: [{ id: `${did}#wallet`, type: "SelfIssuedOPAuthorizationEndpoint", serviceEndpoint: "https://dito.did.md/authorize" }] },
    parameters: { updateKeys: [k1.multikey], nextKeyHashes: [keyHash(k2.multikey)] },
  });
  expect((await post("alice", [next.log[1]!])).status).toBe(204);
  const document = await (await call("alice", "/.well-known/did.json")).json();
  expect(document.service[0]).toMatchObject({ id: "did:web:alice.did.md#wallet", serviceEndpoint: "https://dito.did.md/authorize" });
  expect(checkDidWebShadow(next.log[1]!.state, "did:web:alice.did.md", document)).toEqual({ ok: true });
  // The log can only grow.
  expect((await put("alice", log)).status).toBe(400);
  expect((await put("alice", next.log)).status).toBe(204);
});

test("an update that stops naming the location is refused", async () => {
  fresh();
  const { log, k1, k2 } = await identity();
  await put("alice", log);
  const unnamed = await updateVhLog({ log, signer: k1, now: Date.now() + 2000, document: { ...log[0]!.state, alsoKnownAs: [] }, parameters: { updateKeys: [k1.multikey], nextKeyHashes: [keyHash(k2.multikey)] } });
  const response = await post("alice", [unnamed.log[1]!]);
  expect(response.status).toBe(400);
  expect(await response.text()).toMatch(/must name/);
  expect(await (await call("alice", "/.well-known/did.jsonl")).text()).toBe(serializeVhLog(log));
});

test("an entry that no authorised key signed is refused (here: signed by the retired creating key, and an unsigned one)", async () => {
  fresh();
  const { log, k0, k1 } = await identity();
  await put("alice", log);
  const good = await updateVhLog({ log, signer: k1, now: Date.now() + 2000, parameters: { updateKeys: [k1.multikey], nextKeyHashes: [] } });
  const unsigned = { ...good.log[1]!, proof: [] };
  const response = await post("alice", [unsigned]);
  expect(response.status).toBe(400);
  expect(await response.text()).toMatch(/no proof/);
  // k0 created the log, but pre-rotation committed the next entry to k1: the retired key cannot sign it. (updateVhLog refuses to build it.)
  await expect(updateVhLog({ log, signer: k0, now: Date.now() + 2000, parameters: { updateKeys: [k0.multikey], nextKeyHashes: [] } })).rejects.toThrow(/did not commit/);
});

test("the log is found by its SCID, from any name's host, with public CORS", async () => {
  fresh();
  const { did, log } = await identity();
  await put("alice", log);
  const scid = did.slice(7);
  for (const host of ["alice", "somewhere"]) {
    const response = await call(host, `/log?scid=${scid}`);
    expect(response.status).toBe(200);
    expect(await response.text()).toBe(serializeVhLog(log));
    expect(response.headers.get("access-control-allow-origin")).toBe("*");
    expect(response.headers.get("content-type")).toMatch(/jsonl/);
    expect(response.headers.get("cache-control")).toMatch(/s-maxage/);
  }
  expect((await call("alice", `/witness?scid=${scid}`)).status).toBe(404);
  expect((await call("alice", `/log?scid=${"1".repeat(46)}`)).status).toBe(404);
  expect((await call("alice", "/log")).status).toBe(400);
  expect((await call("alice", "/log?scid=nope")).status).toBe(400);
  expect((await call("alice", "/log?scid=../../etc/passwd")).status).toBe(400);
  const preflight = await call("alice", "/log?scid=x", { method: "OPTIONS" });
  expect(preflight.status).toBe(204);
  expect(preflight.headers.get("access-control-allow-origin")).toBe("*");
});

test("a SCID is published under one name only", async () => {
  fresh();
  const { log, did, k0, k1, k2 } = await identity("alice");
  await put("alice", log);
  // The same identity, renamed in a later entry, cannot also be put under the new name from scratch...
  const renamed = await updateVhLog({ log, signer: k1, now: Date.now() + 2000, document: { ...log[0]!.state, alsoKnownAs: ["did:web:alice.did.md", "did:web:alice2.did.md"] }, parameters: { updateKeys: [k1.multikey], nextKeyHashes: [keyHash(k2.multikey)] } });
  const again = await put("alice2", renamed.log);
  expect(again.status).toBe(400);
  expect(await again.text()).toMatch(/already published under another name/);
  expect(k0.multikey).toBeTruthy();
  expect(did).toBeTruthy();
  expect(store.index.size).toBe(1);
});

test("deactivating removes the did:web document; the log, with its last entry, stays readable", async () => {
  fresh();
  const { did, log, k1 } = await identity();
  await put("alice", log);
  const done = await deactivateVhLog({ log, signer: k1, now: Date.now() + 2000 });
  expect((await post("alice", [done.log[1]!])).status).toBe(204);
  expect((await call("alice", "/.well-known/did.json")).status).toBe(404);
  expect((await call("alice", `/log?scid=${did.slice(7)}`)).status).toBe(200);
});

test("taking the log down (a disconnect request signed by an update key) frees the name and the SCID", async () => {
  fresh();
  const { did, log, k0 } = await identity();
  await put("alice", log);
  const request = { did };
  const proof = await createDataIntegrityProof(request, { privateKey: k0.privateKey, verificationMethod: `did:key:${k0.multikey}#${k0.multikey}`, proofPurpose: "assertionMethod", created: new Date().toISOString() });
  const response = await call("alice", "/.well-known/did.jsonl", { method: "DELETE", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...request, proof }) });
  expect(response.status).toBe(204);
  expect((await call("alice", "/.well-known/did.jsonl")).status).toBe(404);
  expect((await call("alice", "/.well-known/did.json")).status).toBe(404);
  expect((await call("alice", `/log?scid=${did.slice(7)}`)).status).toBe(404);
  expect(store.index.size).toBe(0);
  expect((await put("alice", log)).status).toBe(201);
});

test("witnesses are refused for did:vh, and a store without a SCID index does not publish did:vh at all", async () => {
  fresh();
  const { log } = await identity();
  await put("alice", log);
  const witness = await call("alice", "/.well-known/did-witness.json", { method: "PUT", body: JSON.stringify([{ versionId: log[0]!.versionId, proof: [] }]) });
  expect(witness.status).toBe(400);
  expect(await witness.text()).toMatch(/witnesses are not supported for did:vh/);

  const bare = new MemoryStore();
  delete (bare as { scids?: unknown }).scids;
  setIdentityStore(bare);
  const refused = await put("alice", log);
  expect(refused.status).toBe(400);
  expect(await refused.text()).toMatch(/does not publish did:vh/);
  const capabilities = await (await call("alice", "/.well-known/did-hosting.json")).json();
  expect(capabilities.methods).toEqual(["did:webvh"]);
});

test("the capability document says which methods the host publishes", async () => {
  fresh();
  const capabilities = await (await call("alice", "/.well-known/did-hosting.json")).json();
  expect(capabilities).toMatchObject({ protocol: "webvh-hosting/1", methods: ["did:webvh", "did:vh"] });
});
