#!/usr/bin/env bun
/**
 * Run the did:webvh Hosting Protocol conformance suite against a server.
 *
 *   bun run conformance --domain did.md
 *       hosts throwaway identities at conf-*.did.md (real DNS, real TLS)
 *   bun run conformance --domain did.md --base http://127.0.0.1:8787
 *       same names, but requests go to --base with the right Host header
 *       (a local server standing in for the domain)
 *
 * It creates and deletes throwaway identities; point it only at a server you
 * are allowed to write to. Exit code 0 = every required check passed.
 */
import { parseArgs } from "node:util";
import { formatReport, runConformance } from "./src/conformance.ts";

const { values } = parseArgs({ options: { domain: { type: "string" }, base: { type: "string" } }, strict: true });
if (!values.domain) {
  console.error("Usage: bun run conformance --domain <domain> [--base <url>]");
  process.exit(2);
}
const domain = values.domain;
const base = values.base?.replace(/\/$/, "");
let counter = 0;
const results = await runConformance({
  newLocation: () => `conf-${Date.now().toString(36)}${counter++}.${domain}`,
  fetch: ((input: RequestInfo | URL, init?: RequestInit) => {
    if (!base) return fetch(input, init);
    const url = new URL(String(input));
    const headers = new Headers(init?.headers);
    headers.set("host", url.host);
    return fetch(`${base}${url.pathname}${url.search}`, { ...init, headers });
  }) as typeof fetch,
});
const report = formatReport(results);
console.log(report.text);
process.exit(report.ok ? 0 : 1);
