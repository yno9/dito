/**
 * Local stand-in for Caddy's `try_files {path} /index.html` (see the
 * Caddyfile's app.did.md block) -- serves static files out of dist/, and
 * falls back to dist/index.html for anything that isn't one, so a direct
 * load or reload of e.g. /dashboard works the same locally as it does in
 * production. `python3 -m http.server` (the previous did-md-app command)
 * has no such fallback: it 404s on any path that isn't a real file on
 * disk, which every client-side route other than "/" is.
 */
import { readFile, stat } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";
import { serve } from "../server/serve.ts";

const port = Number(process.env.PORT ?? 8788);
const root = resolve(new URL("../dist", import.meta.url).pathname);
const TYPES: Record<string, string> = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".json": "application/json", ".svg": "image/svg+xml", ".png": "image/png", ".woff2": "font/woff2" };

serve({
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
        const info = await stat(candidate).catch(() => undefined);
        if (info?.isFile()) return new Response(await readFile(candidate), { headers: { "content-type": TYPES[extname(candidate)] ?? "application/octet-stream" } });
      }
    }
    return new Response(await readFile(`${root}/index.html`), { headers: { "content-type": "text/html; charset=utf-8" } });
  },
});

console.log(`did-md-app: serving ${root} on http://127.0.0.1:${port} (SPA fallback to index.html)`);
