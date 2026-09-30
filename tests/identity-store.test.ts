// PLAN9: identity-host.ts's
// per-username storage is now reached exclusively through the IdentityStore
// interface (setIdentityStore/identityFetch), not inline node:fs calls --
// this is the seam a future cloud-worker (Durable-Object-backed) deployment
// plugs into. These tests swap in a plain in-memory store and drive the
// same identityFetch entry point PLAN6's oauth-loopback.test.ts exercises
// against the real filesystem-backed default, proving the abstraction
// actually carries every read/write/exclusive call -- not just some of them
// -- with no disk access at all (DATA_DIR points at a path that is never
// created, so any inline fs fallback would fail loudly instead of silently
// passing).
import { afterEach, expect, test } from "bun:test";
import { buildGenesis, createIdentityMaterial } from "../packages/wallet/src/did-webvh.ts";
import { identityFetch, setIdentityStore, type IdentitySlot, type IdentityStore } from "../server/host/identity-host.ts";

process.env.DATA_DIR = "/nonexistent/plan9-identity-store-test";

class MemoryIdentityStore implements IdentityStore {
  private files = new Map<string, string>();
  private locks = new Map<string, Promise<void>>();
  readCalls = 0; writeCalls = 0; exclusiveCalls = 0;
  private key(username: string, slot: IdentitySlot) { return `${username}/${slot}`; }
  async read(username: string, slot: IdentitySlot): Promise<string | null> {
    this.readCalls += 1;
    return this.files.get(this.key(username, slot)) ?? null;
  }
  async write(username: string, slot: IdentitySlot, content: string): Promise<void> {
    this.writeCalls += 1;
    this.files.set(this.key(username, slot), content);
  }
  async remove(username: string, slot: IdentitySlot): Promise<void> {
    this.files.delete(this.key(username, slot));
  }
  async exclusive<T>(username: string, task: () => Promise<T>): Promise<T> {
    this.exclusiveCalls += 1;
    const before = this.locks.get(username) ?? Promise.resolve();
    let release!: () => void;
    const after = new Promise<void>(resolve => { release = resolve; });
    this.locks.set(username, before.then(() => after));
    await before;
    try { return await task(); } finally { release(); if (this.locks.get(username) === after) this.locks.delete(username); }
  }
}

afterEach(() => { setIdentityStore(new (class extends MemoryIdentityStore {})()); });

function genesisRequest(username: string, jsonl: string): Request {
  return new Request(`https://${username}.did.md/.well-known/did.jsonl`, {
    method: "PUT", headers: { host: `${username}.did.md` }, body: jsonl,
  });
}

test("identityFetch publishes and resolves a genesis entry entirely through a swapped-in IdentityStore, touching no filesystem", async () => {
  const store = new MemoryIdentityStore();
  setIdentityStore(store);
  const username = "plan9user";
  const identity = await createIdentityMaterial();
  const entry = await buildGenesis({ username, domain: "did.md", root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare });
  const jsonl = `${JSON.stringify(entry)}\n`;

  const putRequest = genesisRequest(username, jsonl);
  const putResponse = await identityFetch(putRequest, new URL(putRequest.url));
  expect(putResponse?.status).toBe(201);
  expect(store.writeCalls).toBeGreaterThan(0);
  expect(store.exclusiveCalls).toBe(1);

  const getRequest = new Request(`https://${username}.did.md/.well-known/did.jsonl`, { headers: { host: `${username}.did.md` } });
  const getResponse = await identityFetch(getRequest, new URL(getRequest.url));
  expect(getResponse?.status).toBe(200);
  expect(await getResponse!.text()).toBe(jsonl);

  const availabilityRequest = new Request(`https://did.md/v1/availability?username=${username}`);
  const availabilityResponse = await identityFetch(availabilityRequest, new URL(availabilityRequest.url));
  expect(await availabilityResponse!.json()).toMatchObject({ available: false });

  const unknownAvailabilityRequest = new Request("https://did.md/v1/availability?username=someoneelse");
  const unknownAvailabilityResponse = await identityFetch(unknownAvailabilityRequest, new URL(unknownAvailabilityRequest.url));
  expect(await unknownAvailabilityResponse!.json()).toMatchObject({ available: true });
});

test("identityFetch's per-username exclusive() lock still serializes concurrent writes when the store is swapped", async () => {
  const store = new MemoryIdentityStore();
  setIdentityStore(store);
  const username = "plan9concurrent";
  const identity = await createIdentityMaterial();
  const entry = await buildGenesis({ username, domain: "did.md", root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare });
  const jsonl = `${JSON.stringify(entry)}\n`;

  // Two concurrent PUTs of the identical genesis: the second must observe
  // the first's write (same-prefix check) rather than racing past it and
  // both succeeding as if neither had run -- exactly what exclusive() exists
  // to prevent, now via the swapped-in store's own lock instead of the
  // in-process Map the default FsIdentityStore uses.
  const [first, second] = await Promise.all([
    identityFetch(genesisRequest(username, jsonl), new URL(`https://${username}.did.md/.well-known/did.jsonl`)),
    identityFetch(genesisRequest(username, jsonl), new URL(`https://${username}.did.md/.well-known/did.jsonl`)),
  ]);
  const statuses = [first!.status, second!.status].sort();
  // One creates (201), the other sees the identical log already published
  // and is treated as a no-op republish (204) -- either way, exactly one
  // did:webvh log resource exists afterward, never a corrupted merge.
  expect(statuses).toEqual([201, 204]);
});
