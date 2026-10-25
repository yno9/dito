// did.md's host in-process: identityFetch over an in-memory store (with the SCID index), and a fetch that reaches it
// the way a request for https://<name>.did.md/... would, with the Host header the real one is routed by.
import { identityFetch, setIdentityStore, type IdentitySlot, type IdentityStore } from "../../server/host/identity-host.ts";

process.env.DATA_DIR ??= "/nonexistent/vh-host-test";

export class MemoryStore implements IdentityStore {
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

/** A new empty host. Returns the store. */
export function freshHost(): MemoryStore {
  const store = new MemoryStore();
  setIdentityStore(store);
  return store;
}
export function resetHost(): void { setIdentityStore(new MemoryStore()); }

export const viaHost = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = new URL(input instanceof Request ? input.url : String(input));
  const headers = new Headers(init?.headers);
  headers.set("host", url.host);
  const { cache: _cache, ...rest } = init ?? {};
  return (await identityFetch(new Request(url, { ...rest, headers }), url)) ?? new Response("not found\n", { status: 404 });
}) as typeof fetch;
