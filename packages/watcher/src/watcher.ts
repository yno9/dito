/**
 * A watcher for did:vh (didvh-spec: Watchers; VH-Log: Watcher HTTP API Operations).
 *
 * It does one thing: hold the newest log of each identity it has been asked to watch, verified in full, and say so when a log
 * forks. It never believes a log because of who sent it; a notification only says "look again": the log is fetched from the web
 * location, verified (SCID, hash chain, signatures), and compared with the one held.
 *
 *   GET  /log?scid=<SCID>          the log held, or 404
 *   POST /log?id=<did:vh:SCID[?src=<location>]>   "there is a newer log". With a `src`: fetch it there. Without one the request
 *                                  carries the complete log (text/jsonl), as the specification requires. (A body-less
 *                                  notification for a log already held is followed up where it was last fetched.)
 *   POST /log/delete?scid=<SCID>   the operator's token only (the spec leaves who may ask to the watcher's governance)
 *   GET  /witness, /resource       501: not supported yet (witnesses are refused by dito and biset)
 *
 * Who may be watched is the operator's list (`allow`): a notification makes this server fetch a URL, and a watcher that fetched
 * whatever it was told would be an open proxy and an open store.
 *
 * The handler takes and gives web-standard Request/Response and a `WatcherStore`, so the same code runs on Node and on Workers.
 */
import { fetchVhLog, isScid, locationsOf, parseVhLog, resolveVhLog, VhResolutionError, type VhLogEntry } from "../../vh/src/index.ts";
import type { Fork, WatchedLog, WatcherStore } from "./store.ts";

export type WatcherAllow = {
  /** Hosts whose logs may be watched: `alice.did.md`, or `*.did.md` for every name under it. */
  hosts?: readonly string[];
  /** SCIDs that may be watched wherever their log is. */
  scids?: readonly string[];
};

export type WatcherOptions = {
  store: WatcherStore;
  allow: WatcherAllow;
  /** The bearer token that may delete a log; without one, deleting is refused. */
  adminToken?: string;
  fetch?: typeof fetch;
  now?: () => Date;
  /** The largest log accepted, in bytes. */
  maxBytes?: number;
  /** Passed to the location parser (tests allow `http://localhost`). */
  srcOptions?: { allowLoopback?: boolean };
};

const CORS = { "access-control-allow-origin": "*", "access-control-allow-methods": "GET, POST, OPTIONS", "access-control-allow-headers": "authorization, content-type" };

function json(status: number, body: unknown, extra: Record<string, string> = {}) {
  return new Response(`${JSON.stringify(body)}\n`, { status, headers: { ...CORS, "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...extra } });
}
const fail = (status: number, error: string, message: string) => json(status, { error, message });

/** Whether `host` is one the operator listed (`*.did.md` matches `alice.did.md`, not `did.md` or `evil-did.md`). */
export function hostAllowed(host: string, hosts: readonly string[] = []): boolean {
  const lower = host.toLowerCase();
  return hosts.some(entry => {
    const pattern = entry.toLowerCase();
    return pattern.startsWith("*.") ? lower.endsWith(pattern.slice(1)) && lower.length > pattern.length - 1 : lower === pattern;
  });
}

/** The hosts a document says it is published at: its `?src=` aliases and the plain-host did:web DIDs it names. */
function placesOf(did: string, document: Record<string, any>, srcOptions?: { allowLoopback?: boolean }): string[] {
  const hosts = locationsOf(did, document, srcOptions).map(location => new URL(location.src).hostname);
  for (const alias of Array.isArray(document.alsoKnownAs) ? document.alsoKnownAs : []) {
    const host = typeof alias === "string" ? /^did:web:([a-z0-9-]+(?:\.[a-z0-9-]+)+)$/.exec(alias)?.[1] : undefined;
    if (host) hosts.push(host);
  }
  return hosts;
}

/** `did:vh:<SCID>` or `did:vh:<SCID>?src=<location>` as given in a notification's `id`. */
function parseId(id: string): { scid: string; did: string; src?: string } | undefined {
  const [did = "", query] = id.split("?", 2) as [string, string | undefined];
  const match = /^did:vh:([^:/?#]+)$/.exec(did);
  if (!match || !isScid(match[1])) return undefined;
  const src = query === undefined ? undefined : new URLSearchParams(query).get("src") ?? undefined;
  return { scid: match[1], did, ...(src ? { src } : {}) };
}

export function createWatcher(options: WatcherOptions) {
  const { store } = options;
  const now = options.now ?? (() => new Date());

  async function get(url: URL) {
    const scid = url.searchParams.get("scid") ?? "";
    if (!isScid(scid)) return fail(400, "invalidScid", "scid must be a SCID.");
    const held = await store.get(scid);
    if (!held) return new Response("not found\n", { status: 404, headers: { ...CORS, "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });
    return new Response(held.text, {
      headers: {
        ...CORS, "content-type": "text/jsonl; charset=utf-8", "cache-control": "public, max-age=0, s-maxage=10",
        // A fork is a fact about the identity worth telling every reader: the owner showed two continuations of one history.
        ...(held.forks.length ? { "x-did-vh-forks": String(held.forks.length) } : {}),
      },
    });
  }

  async function notify(request: Request, url: URL) {
    const given = parseId(url.searchParams.get("id") ?? "");
    if (!given) return fail(400, "invalidId", "id must be did:vh:<SCID> or did:vh:<SCID>?src=<location>.");
    const held = await store.get(given.scid);
    const maxBytes = options.maxBytes ?? 4 * 1024 * 1024;
    const body = given.src ? "" : (await request.text());
    if (body.length > maxBytes) return fail(413, "tooLarge", `The log is larger than ${maxBytes} bytes.`);
    const src = body.trim() ? undefined : given.src ?? held?.source;
    if (!body.trim() && !src) return fail(400, "noLog", "Give id=did:vh:<SCID>?src=<location>, or send the complete log as the body (text/jsonl).");

    let log: VhLogEntry[];
    let source: string | undefined = held?.source;
    try {
      if (src) {
        // A notification makes this server fetch a URL: only a place the operator listed (or a listed SCID) is ever asked.
        let host: string;
        try { host = new URL(src).hostname; } catch { return fail(400, "invalidSrc", "src is not a URL."); }
        if (!(options.allow.scids?.includes(given.scid) || hostAllowed(host, options.allow.hosts))) return fail(403, "notWatched", "This watcher is not set up to watch that identity.");
        log = (await fetchVhLog(src, { ...options.srcOptions, ...(options.fetch ? { fetch: options.fetch } : {}), maxBytes })).log;
        source = src;
      } else {
        log = parseVhLog(body);
      }
      const resolution = await resolveVhLog(given.did, log, { now: now().getTime() });
      if (!src) {
        // Nothing is fetched for a pushed log, so the only question is whether it is one this watcher is set up to hold: a listed SCID,
        // or a log whose newest document names a place the operator listed (the same rule a host applies before it takes a log).
        const places = resolution.doc ? placesOf(given.did, resolution.doc, options.srcOptions) : [];
        if (!(options.allow.scids?.includes(given.scid) || places.some(host => hostAllowed(host, options.allow.hosts)))) return fail(403, "notWatched", "This watcher is not set up to watch that identity.");
      }
    } catch (cause) {
      if (cause instanceof VhResolutionError) return fail(cause.code === "notFound" ? 404 : 422, cause.code, cause.message);
      return fail(502, "fetchFailed", (cause as Error).message);
    }

    const versionIds = log.map(entry => entry.versionId);
    const text = log.map(entry => JSON.stringify(entry)).join("\n") + "\n";
    const stamp = now().toISOString();
    if (!held) {
      await store.put({ scid: given.scid, did: given.did, text, versionIds, ...(source ? { source } : {}), forks: [], updatedAt: stamp });
      return json(200, { did: given.did, status: "stored", versionNumber: versionIds.length });
    }
    // Where do the two logs part? Every versionId carries a hash chained to its predecessor, so one log extends the other exactly
    // when the shorter one is a prefix of the longer one.
    const common = Math.min(versionIds.length, held.versionIds.length);
    let differsAt = -1;
    for (let index = 0; index < common; index += 1) if (versionIds[index] !== held.versionIds[index]) { differsAt = index; break; }
    if (differsAt >= 0) {
      const fork: Fork = { versionNumber: differsAt + 1, versionId: versionIds[differsAt]!, seenAt: stamp, source: src ?? "pushed" };
      if (!held.forks.some(known => known.versionNumber === fork.versionNumber && known.versionId === fork.versionId)) {
        await store.put({ ...held, forks: [...held.forks, fork], updatedAt: stamp });
      }
      return json(409, { did: given.did, status: "forked", versionNumber: fork.versionNumber, held: held.versionIds[differsAt], seen: fork.versionId });
    }
    if (versionIds.length > held.versionIds.length) {
      await store.put({ ...held, text, versionIds, ...(source ? { source } : {}), updatedAt: stamp });
      return json(200, { did: given.did, status: "updated", versionNumber: versionIds.length });
    }
    return json(200, { did: given.did, status: versionIds.length === held.versionIds.length ? "unchanged" : "stale", versionNumber: held.versionIds.length });
  }

  async function remove(request: Request, url: URL) {
    const token = options.adminToken;
    if (!token || request.headers.get("authorization") !== `Bearer ${token}`) return fail(403, "notAllowed", "Only the operator may delete a log from this watcher.");
    const scid = url.searchParams.get("scid") ?? "";
    if (!isScid(scid)) return fail(400, "invalidScid", "scid must be a SCID.");
    return (await store.delete(scid)) ? json(200, { scid, status: "deleted" }) : fail(404, "notFound", "No such log.");
  }

  return {
    async handle(request: Request): Promise<Response> {
      const url = new URL(request.url);
      if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: { ...CORS, "access-control-max-age": "86400" } });
      if (url.pathname === "/healthz" && request.method === "GET") return json(200, { ok: true, service: "did-vh-watcher" });
      if (url.pathname === "/log" && request.method === "GET") return get(url);
      if (url.pathname === "/log" && request.method === "POST") return notify(request, url);
      if (url.pathname === "/log/delete" && request.method === "POST") return remove(request, url);
      if (url.pathname === "/witness" || url.pathname.startsWith("/resource")) return fail(501, "notSupported", "Witness files and resources are not supported by this watcher.");
      return fail(404, "notFound", "No such endpoint.");
    },
  };
}
