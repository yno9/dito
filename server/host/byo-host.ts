/**
 * One domain, one did:vh identity, kept as plain files.
 *
 * The write side of SPEC-vh-hosting.md for a bring-your-own domain: a PUT/POST/DELETE
 * lands in <ROOT>/.well-known/did.jsonl (with the did:web document it derives, did.json, beside
 * it), so the static file server that already serves ROOT keeps answering every read. Behind
 * Caddy, send it the writes only:
 *
 *   handle @write { reverse_proxy 127.0.0.1:8796 }      # @write method PUT POST DELETE OPTIONS
 *
 *   DOMAIN=digitalcommons.jp ROOT=/opt/dc/dist PORT=8796 node server/host/byo-host.ts
 *
 * The identity is bound to the domain the same way a did.md name is: the log's current document must
 * name `did:web:<domain>` in `alsoKnownAs`.
 */
import { mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { deriveDidWebDocument, parseVhLog, serializeVhLog, validateVhLogAt, verifyDataIntegrityProof, type Proof } from "../../packages/vh/src/index.ts";
import { serve } from "../serve.ts";

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, PUT, DELETE, OPTIONS",
  "access-control-allow-headers": "content-type",
  "access-control-max-age": "86400",
};
const MAX_LOG_BYTES = 256 << 10;

export function createByoHost({ root, domain }: { root: string; domain: string }) {
  const logFile = join(root, ".well-known/did.jsonl");
  const webFile = join(root, ".well-known/did.json");
  const webDid = `did:web:${domain}`;
  const read = (file: string) => { try { return readFileSync(file, "utf8"); } catch { return undefined; } };
  const write = (file: string, text: string) => {
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(`${file}.tmp`, text);
    renameSync(`${file}.tmp`, file); // atomic: a reader sees the old file or the new one
  };
  const reply = (status: number, body?: string) =>
    new Response(body === undefined ? null : body.endsWith("\n") ? body : `${body}\n`, { status, headers: { ...CORS, ...(body === undefined ? {} : { "content-type": "text/plain; charset=utf-8" }), "cache-control": "no-cache" } });
  let queue: Promise<unknown> = Promise.resolve();
  const exclusive = <T>(task: () => Promise<T>): Promise<T> => { const run = queue.catch(() => undefined).then(task); queue = run.catch(() => undefined); return run; };

  return async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    if (url.pathname === "/.well-known/did-hosting.json" && request.method === "GET") {
      return new Response(`${JSON.stringify({ protocol: "vh-hosting/1", writes: true, delete: true, maxLogBytes: MAX_LOG_BYTES, methods: ["did:vh"] })}\n`, { headers: { ...CORS, "content-type": "application/json; charset=utf-8", "cache-control": "no-cache" } });
    }
    if (url.pathname === "/.well-known/did.json" && request.method === "GET") {
      const body = read(webFile);
      return body === undefined ? reply(404, "not found") : new Response(body, { headers: { ...CORS, "content-type": "application/json; charset=utf-8", "cache-control": "no-cache" } });
    }
    if (url.pathname !== "/.well-known/did.jsonl") return reply(404, `${domain} hosts one identity, at /.well-known/`);
    if (request.headers.get("host")?.split(":")[0]?.toLowerCase() !== domain && url.hostname !== domain) return reply(403, `this host serves ${domain} only`);
    if (request.method === "GET") { const body = read(logFile); return body === undefined ? reply(404, "not found") : new Response(body, { headers: { ...CORS, "content-type": "text/jsonl; charset=utf-8", "cache-control": "no-cache" } }); }
    try {
      return await exclusive(async () => {
        const existing = read(logFile);
        if (request.method === "DELETE") {
          if (existing === undefined) return reply(404, "not found");
          const current = await validateVhLogAt(parseVhLog(existing), { webDid });
          const { proof, ...document } = JSON.parse(await request.text()) as { did?: string; proof?: Proof };
          if (document.did !== current.did) return reply(400, "disconnect request.did does not match the published DID");
          if (!proof || !Number.isFinite(Date.parse(proof.created ?? "")) || Math.abs(Date.now() - Date.parse(proof.created!)) > 5 * 60_000) return reply(400, "disconnect proof is outside its accepted time window");
          if (!(await verifyDataIntegrityProof(document, proof, current.parameters.updateKeys))) return reply(400, "disconnect request has no valid current update-key proof");
          rmSync(logFile, { force: true }); rmSync(webFile, { force: true });
          return reply(204);
        }
        if (request.method !== "PUT" && request.method !== "POST") return reply(405, "method not allowed");
        const text = await request.text();
        if (new TextEncoder().encode(text).byteLength > MAX_LOG_BYTES) return reply(413, "body too large");
        const incoming = parseVhLog(text);
        let next;
        if (request.method === "POST") {
          if (existing === undefined) return reply(400, "POST requires an existing log; publish genesis with PUT");
          if (incoming[0]!.parameters.scid) return reply(400, "POST contains a genesis entry; use PUT for a full log");
          next = [...parseVhLog(existing), ...incoming];
        } else {
          if (existing !== undefined && !serializeVhLog(incoming).startsWith(existing)) return reply(400, "PUT must preserve the existing log as a byte-for-byte prefix");
          next = incoming;
        }
        const checked = await validateVhLogAt(next, { webDid });
        write(logFile, serializeVhLog(next));
        if (checked.parameters.deactivated) rmSync(webFile, { force: true });
        else write(webFile, `${JSON.stringify(deriveDidWebDocument(checked.latest.state, webDid))}\n`);
        return reply(existing === undefined ? 201 : 204);
      });
    } catch (error) {
      return reply(400, error instanceof Error ? error.message : "invalid request");
    }
  };
}

if (import.meta.main) {
  const domain = process.env.DOMAIN, root = process.env.ROOT;
  if (!domain || !root) throw new Error("Set DOMAIN (e.g. digitalcommons.jp) and ROOT (the directory the web server serves).");
  const host = createByoHost({ root, domain });
  // Behind a TLS-terminating proxy the request arrives as http://; DIDs name https://.
  serve({ port: Number(process.env.PORT ?? 8796), hostname: "127.0.0.1", fetch: (request: Request) => { const url = new URL(request.url); url.protocol = "https:"; return host(new Request(url, request)); } });
}
