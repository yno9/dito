/**
 * did.md process entry point.
 *
 * This file only composes two independent modules into one serve():
 *
 *   - identity-host.ts: the essential, non-optional did:webvh host. This is
 *     what did.md fundamentally IS.
 *   - oauth-server.ts: an optional OAuth 2.0 / OID4VP convenience layer for
 *     relying parties that lack their own backend, and for continued/
 *     refreshable access. Not required by SIOPv2/OID4VP itself (see that
 *     file's own header) and not required by identity-host.ts, which never
 *     imports from it. See ARC.md §3/§3.4 for the full reasoning.
 *
 * Splitting this way (2026-09-21) makes that dependency direction, and
 * which half is essential, read directly from the codebase.
 */
import { identityFetch, cors, IDENTITY_DOMAIN, Invalid, json, PORT, text } from "./host/identity-host.ts";
import { oauthCors, oauthFetch } from "./oauth/oauth-server.ts";
import { serve } from "./serve.ts";

// The single shared catch-all (see the top-level try/catch around route
// dispatch below) has to pick the right CORS policy itself, since it fires
// for errors from every route -- unlike success responses, which already
// pick per-route via json()/oauthJson(). Getting this wrong is not cosmetic:
// an OAuth-path error response without access-control-allow-origin makes
// the browser report an opaque "CORS policy" failure instead of the actual
// 400/500 body, and a caller whose error-handling relies on reading that
// body (see biset's restoreDidMdWalletSession) never even reaches its own
// catch block -- the fetch() promise itself rejects first (found live,
// 2026-09-21, t.biset.md: a stale stored session's expected 400 from
// /v1/oauth/device-refresh surfaced as an uncatchable "Failed to fetch").
function fail(request: Request, error: unknown) {
  const status = error instanceof Invalid ? 400 : 500;
  const message = error instanceof Invalid ? error.message : "internal error";
  const pathname = (() => { try { return new URL(request.url).pathname; } catch { return ""; } })();
  const corsHeaders = pathname.startsWith("/v1/oauth/") ? oauthCors(request) : cors(request);
  return new Response(`${message}\n`, { status, headers: { ...corsHeaders, "content-type": "text/plain; charset=utf-8" } });
}

const app = serve({
  port: PORT,
  hostname: process.env.HOST ?? "127.0.0.1",
  async fetch(request) {
    try {
      const url = new URL(request.url);
      // /.well-known/* preflights belong to identityFetch (the did:webvh Hosting Protocol resources allow any origin).
      if (request.method === "OPTIONS" && !url.pathname.startsWith("/.well-known/")) return new Response(null, { status: 204, headers: url.pathname.startsWith("/v1/oauth/") ? oauthCors(request) : cors(request) });
      if (url.pathname === "/healthz" && request.method === "GET") return json(request, { ok: true, service: "did.md", method: "did:webvh:1.0", identityDomain: IDENTITY_DOMAIN });
      const oauthResponse = await oauthFetch(request, url); if (oauthResponse) return oauthResponse;
      const identityResponse = await identityFetch(request, url); if (identityResponse) return identityResponse;
      return text(request, "not found", 404);
    } catch (error) { console.error(error); return fail(request, error); }
  },
});
console.info(`did.md API listening on http://${app.hostname}:${app.port}; publishing *.${IDENTITY_DOMAIN}`);
