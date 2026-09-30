/**
 * Local stand-in for Caddy's `try_files {path} /index.html` (see the
 * Caddyfile's app.did.md block) -- serves static files out of dist/, and
 * falls back to dist/index.html for anything that isn't one, so a direct
 * load or reload of e.g. /dashboard works the same locally as it does in
 * production. `python3 -m http.server` (the previous did-md-app command)
 * has no such fallback: it 404s on any path that isn't a real file on
 * disk, which every client-side route other than "/" is.
 */
import { resolve, sep } from "node:path";

const port = Number(Bun.env.PORT ?? 8788);
const root = resolve(new URL("../dist", import.meta.url).pathname);
const indexHtml = Bun.file(`${root}/index.html`);

Bun.serve({
  port,
  // Loopback only -- this serves dist/ with no auth of its own, and has no
  // reason to be reachable from anything but this machine.
  hostname: "127.0.0.1",
  async fetch(request) {
    const url = new URL(request.url);
    const path = decodeURIComponent(url.pathname);
    if (path !== "/") {
      // resolve() collapses ".." before the containment check runs, so a
      // request like /../../etc/passwd can't walk the candidate path
      // outside root -- it fails startsWith(root + sep) and falls through
      // to the same index.html fallback as any other unmatched route.
      const candidate = resolve(root + path);
      if (candidate === root || candidate.startsWith(root + sep)) {
        const file = Bun.file(candidate);
        if (await file.exists()) return new Response(file);
      }
    }
    return new Response(indexHtml, { headers: { "content-type": "text/html; charset=utf-8" } });
  },
});

console.log(`did-md-app: serving ${root} on http://127.0.0.1:${port} (SPA fallback to index.html)`);
