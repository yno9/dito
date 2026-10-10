/**
 * A minimal, storage-agnostic server for the did:webvh Hosting Protocol
 * (SPEC-webvh-hosting.md) built on nothing but didwebvh-ts: a `(Request) =>
 * Response` handler any runtime can mount (Node, Deno, Workers, Node's fetch
 * adapters). It exists to prove the protocol does not depend on did.md's
 * server and to give a third party a starting point; it is deliberately not
 * did.md's host (no naming policy, quotas, mirrors or extra resources).
 */
import { didToLogUrl } from "./url.ts";
import { parseLog, resolveLog, serializeLog, currentParameters, type DIDLog } from "./log.ts";
import { verifyDataIntegrityProof, type Proof } from "./proof.ts";

export type ReferenceStore = {
  get(key: string): Promise<string | undefined> | string | undefined;
  set(key: string, value: string): Promise<void> | void;
  delete(key: string): Promise<void> | void;
};

export type ReferenceHostOptions = {
  store?: ReferenceStore;
  /** Server policy: refuse a location (returns a reason, or undefined to allow). */
  refuse?(host: string): string | undefined;
  maxLogBytes?: number;
};

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, PUT, DELETE, OPTIONS",
  "access-control-allow-headers": "content-type",
  "access-control-max-age": "86400",
};

export function createReferenceHost(options: ReferenceHostOptions = {}): (request: Request) => Promise<Response> {
  const map = new Map<string, string>();
  const store: ReferenceStore = options.store ?? { get: key => map.get(key), set: (key, value) => { map.set(key, value); }, delete: key => { map.delete(key); } };
  const maxLogBytes = options.maxLogBytes ?? 16 << 20;
  const locks = new Map<string, Promise<unknown>>();
  const reply = (status: number, body?: string, type = "text/plain; charset=utf-8") =>
    new Response(body === undefined ? null : body.endsWith("\n") ? body : `${body}\n`, { status, headers: { ...CORS, ...(body === undefined ? {} : { "content-type": type }), "cache-control": "no-cache" } });
  // Writes to one location are serialized (SPEC §3).
  const exclusive = <T>(key: string, fn: () => Promise<T>): Promise<T> => {
    const run = (locks.get(key) ?? Promise.resolve()).catch(() => undefined).then(fn);
    locks.set(key, run.catch(() => undefined));
    return run;
  };

  async function validate(log: DIDLog, url: URL, witness: string | undefined) {
    const proofs = witness ? JSON.parse(witness) : undefined;
    await resolveLog(log, proofs ? { witnessProofs: proofs } : {});
    const did = log.at(-1)!.state.id as string;
    if (didToLogUrl(did) !== `${url.origin}${url.pathname}`) throw new Error("current state.id does not designate this location");
  }

  return async function handle(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    if (url.pathname === "/.well-known/did-hosting.json" && request.method === "GET") {
      return reply(200, JSON.stringify({ protocol: "webvh-hosting/1", writes: true, delete: true, witness: true, maxLogBytes }), "application/json");
    }
    const match = /(^|\/)(did\.jsonl|did-witness\.json)$/.exec(url.pathname);
    if (!match) return reply(404, "not found");
    const resource = match[2]!;
    const logKey = `${url.origin}${url.pathname.replace(/did-witness\.json$/, "did.jsonl")}`;
    const witnessKey = logKey.replace(/did\.jsonl$/, "did-witness.json");
    const key = resource === "did.jsonl" ? logKey : witnessKey;

    try {
      if (request.method === "GET") {
        const body = await store.get(key);
        return body === undefined ? reply(404, "not found") : reply(200, body, resource === "did.jsonl" ? "text/jsonl; charset=utf-8" : "application/json");
      }
      return await exclusive(logKey, async () => {
        const existing = await store.get(logKey);
        const witness = await store.get(witnessKey);
        const refusal = options.refuse?.(url.host);
        if (refusal && request.method !== "DELETE") return reply(403, refusal);

        if (request.method === "DELETE") {
          if (resource !== "did.jsonl") return reply(405, "method not allowed");
          if (existing === undefined) return reply(404, "not found");
          const current = parseLog(existing);
          const body = JSON.parse(await request.text()) as { did?: string; proof?: Proof };
          const { proof, ...document } = body;
          if (document.did !== current.at(-1)!.state.id) return reply(400, "disconnect request.did does not match the published DID");
          if (!proof || !Number.isFinite(Date.parse(proof.created ?? "")) || Math.abs(Date.now() - Date.parse(proof.created!)) > 5 * 60_000) return reply(400, "disconnect proof is outside its accepted time window");
          if (!(await verifyDataIntegrityProof(document, proof, (currentParameters(current).updateKeys ?? [])))) return reply(400, "disconnect request has no valid current update-key proof");
          await store.delete(logKey); await store.delete(witnessKey);
          return reply(204);
        }
        if (request.method !== "PUT" && !(resource === "did.jsonl" && request.method === "POST")) return reply(405, "method not allowed");

        const text = await request.text();
        if (new TextEncoder().encode(text).byteLength > maxLogBytes) return reply(413, "body too large");
        if (resource === "did-witness.json") {
          const parsed = JSON.parse(text);
          if (!Array.isArray(parsed)) return reply(400, "did-witness.json must be an array");
          if (existing !== undefined) await validate(parseLog(existing), url, text);
          await store.set(witnessKey, text);
          return reply(204);
        }
        const incoming = parseLog(text);
        let next: DIDLog;
        if (request.method === "POST") {
          if (existing === undefined) return reply(400, "POST requires an existing log; publish genesis with PUT");
          if (incoming[0]!.parameters.scid) return reply(400, "POST contains a genesis entry; use PUT for a full log");
          next = [...parseLog(existing), ...incoming];
        } else {
          if (existing !== undefined && !serializeLog(incoming).startsWith(existing)) return reply(400, "PUT must preserve the existing log as a byte-for-byte prefix");
          next = incoming;
        }
        await validate(next, url, witness);
        await store.set(logKey, serializeLog(next));
        return reply(existing === undefined ? 201 : 204);
      });
    } catch (error) {
      return reply(400, error instanceof Error ? error.message : "invalid request");
    }
  };
}
