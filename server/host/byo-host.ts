/**
 * One domain, one did:webvh identity, kept as plain files.
 *
 * The write side of SPEC-webvh-hosting.md for a bring-your-own domain: a PUT/POST/DELETE
 * lands in <ROOT>/.well-known/did.jsonl (with its did:web mirror, did.json, beside it), so
 * the static file server that already serves ROOT keeps answering every read. Behind
 * Caddy, send it the writes only:
 *
 *   handle @write { reverse_proxy 127.0.0.1:8796 }      # @write method PUT POST DELETE OPTIONS
 *
 *   DOMAIN=digitalcommons.jp ROOT=/opt/dc/dist PORT=8796 bun server/host/byo-host.ts
 */
import { mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { createReferenceHost, parseLog } from "../../packages/webvh/src/index.ts";
import { mirrorDocument } from "../../packages/wallet/src/webvh-core.ts";

export function createByoHost({ root, domain }: { root: string; domain: string }) {
  // The only two locations this host has: the DID base of an apex domain.
  const path = (key: string) => {
    const name = new URL(key).pathname;
    if (name !== "/.well-known/did.jsonl" && name !== "/.well-known/did-witness.json") throw new Error(`${domain} hosts one identity, at /.well-known/`);
    return join(root, name);
  };
  const didJson = (log: string) => {
    const { state } = parseLog(log).at(-1)!;
    return `${JSON.stringify(mirrorDocument(state, state.id, { hostedResources: false }))}\n`;
  };
  const write = (file: string, text: string) => {
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(`${file}.tmp`, text);
    renameSync(`${file}.tmp`, file); // atomic: a reader sees the old file or the new one
  };

  const host = createReferenceHost({
    refuse: requested => requested === domain ? undefined : `this host serves ${domain} only`,
    store: {
      get: key => { try { return readFileSync(path(key), "utf8"); } catch { return undefined; } },
      set: (key, value) => {
        write(path(key), value);
        if (key.endsWith("did.jsonl")) write(join(root, ".well-known/did.json"), didJson(value));
      },
      delete: key => {
        rmSync(path(key), { force: true });
        if (key.endsWith("did.jsonl")) rmSync(join(root, ".well-known/did.json"), { force: true });
      },
    },
  });

  // Behind a TLS-terminating proxy the request arrives as http://; DIDs name https://.
  return (request: Request) => { const url = new URL(request.url); url.protocol = "https:"; return host(new Request(url, request)); };
}

if (import.meta.main) {
  const domain = Bun.env.DOMAIN, root = Bun.env.ROOT;
  if (!domain || !root) throw new Error("Set DOMAIN (e.g. digitalcommons.jp) and ROOT (the directory the web server serves).");
  Bun.serve({ port: Number(Bun.env.PORT ?? 8796), hostname: "127.0.0.1", fetch: createByoHost({ root, domain }) });
}
