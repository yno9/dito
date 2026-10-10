/**
 * Bundles the client application into a single dist/index.html openable directly via file://.
 * All JavaScript and page templates are inlined as one module script; styles.css
 * is inlined as one <style>. The one font this app uses (MuseoModerno, for the
 * "dito" logotype) is itself base64-inlined as a subsetted @font-face inside
 * styles.css -- there is no remaining external request of any kind.
 */
import { build } from "esbuild";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";

const PUBLIC = "public";
const DIST = "dist";

const result = await build({
  entryPoints: ["client/app.ts"],
  bundle: true,
  platform: "browser",
  format: "esm",
  minify: false,
  loader: { ".html": "text" },
  write: false,
  logLevel: "error",
});

// The application bundle is embedded in an inline script below. Dependencies may
// legitimately contain the literal `</script>` inside a JavaScript string; escape
// it so it cannot terminate the HTML script element while the browser parses it.
const bundle = result.outputFiles[0]!.text.replace(/<\/script/gi, "<\\/script");
const css = readFileSync(`${PUBLIC}/styles.css`, "utf8");
let html = readFileSync(`${PUBLIC}/index.html`, "utf8");

html = html.replace(
  /<link rel="stylesheet" href="\/styles\.css[^"]*">/,
  `<style>\n${css}\n</style>`,
);
html = html.replace(
  /<script type="module" src="\/build\/app\.js[^"]*"><\/script>/,
  // A replacement callback is essential here: a bundled dependency can contain
  // `$&`, `$'`, etc., which String.replace would otherwise expand as replacement
  // tokens and corrupt the generated JavaScript.
  () => `<script type="module">\n${bundle}\n</script>`,
);

mkdirSync(DIST, { recursive: true });
writeFileSync(`${DIST}/index.html`, html);
// index.html is intentionally the only distributed tool. Remove obsolete
// standalone copies so a local user cannot accidentally open an older UI.
rmSync(`${DIST}/did.html`, { force: true });
rmSync(`${DIST}/eic-recovery.html`, { force: true });
console.log(`wrote ${DIST}/index.html`);
