/**
 * did:webvh host as a plain HTTP process: the whole did.md identity host
 * (server/host/identity-host.ts, which implements SPEC-webvh-hosting.md) and
 * nothing else -- no OAuth layer, which runs in oidc-bridge.
 *
 * This is what runs on the VPS behind Caddy and Cloudflare's CDN:
 *
 *   browser / resolver ──> Cloudflare CDN ──(miss, or any write)──> Caddy ──> this
 *
 * Public reads carry `s-maxage` (see PUBLIC_READ_CACHE_SECONDS), so the CDN
 * answers nearly all of them; this process sees cache misses and writes. Data
 * lives on local disk (FsIdentityStore, DATA_DIR). Build: `bun build --compile
 * server/host/http-server.ts` (deploy.sh identity).
 */
import { identityFetch, publicDocumentCors, cors, IDENTITY_DOMAIN, Invalid, PORT, text } from "./identity-host.ts";

function fail(request: Request, error: unknown) {
  const status = error instanceof Invalid ? 400 : 500;
  const message = error instanceof Invalid ? error.message : "internal error";
  // Same rule as identityFetch: protocol resources are readable from any origin.
  const pathname = (() => { try { return new URL(request.url).pathname; } catch { return ""; } })();
  const headers = pathname.startsWith("/.well-known/") ? publicDocumentCors() : cors(request);
  return new Response(`${message}\n`, { status, headers: { ...headers, "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });
}

const app = Bun.serve({
  port: PORT,
  hostname: Bun.env.HOST ?? "127.0.0.1",
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (url.pathname === "/healthz" && request.method === "GET") {
        return new Response(`${JSON.stringify({ ok: true, service: "did.md", method: "did:webvh:1.0", identityDomain: IDENTITY_DOMAIN })}\n`, {
          headers: { ...publicDocumentCors(), "content-type": "application/json", "cache-control": "no-store" },
        });
      }
      // Preflights for /.well-known/* belong to identityFetch (any origin allowed).
      if (request.method === "OPTIONS" && !url.pathname.startsWith("/.well-known/")) return new Response(null, { status: 204, headers: cors(request) });
      return (await identityFetch(request, url)) ?? text(request, "not found", 404);
    } catch (error) {
      console.error(error);
      return fail(request, error);
    }
  },
});
console.info(`did.md identity host listening on http://${app.hostname}:${app.port}; publishing *.${IDENTITY_DOMAIN}`);
