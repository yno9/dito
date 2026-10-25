/**
 * Where a did:vh log is fetched from: the `src` of didvh-spec ("Web Locations").
 * A web location is the base URL under which `did.jsonl` is published. The
 * layout is did:webvh's, so a dito host serves `https://alice.did.md` at
 * `/.well-known/did.jsonl` exactly as it serves a did:webvh log.
 *
 * This is also the SSRF guard for anything that fetches on behalf of someone
 * else: a domain name (never an IP address), https, no credentials, no query,
 * no redirects, a bounded body.
 */
import { VhResolutionError } from "./verify.ts";
import { parseVhLog, type VhLogEntry } from "./log.ts";

const LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
const DOMAIN = new RegExp(`^(?=.{1,253}$)(?:${LABEL}\\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`);
const LOOPBACK = /^(?:localhost|127(?:\.\d{1,3}){3}|\[::1\])$/;
const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;

export type SrcOptions = {
  /** Allow `http` to a loopback host: for a resolver that runs next to its client (development, tests). */
  allowLoopback?: boolean;
};

const refuse = (message: string) => new VhResolutionError("invalidOptions", message);

/** A validated web location: its origin and its path segments in the form they were written. */
export type WebLocation = { origin: string; host: string; port?: number; segments: string[] };

export function parseWebLocation(src: unknown, options: SrcOptions = {}): WebLocation {
  if (typeof src !== "string") throw refuse("src must be a string.");
  const match = /^(https?):\/\/([^/?#@\\]+)((?:\/[^?#\\]*)?)$/i.exec(src);
  if (!match) throw refuse("src must be an absolute https URL without credentials, query or fragment.");
  const scheme = match[1]!.toLowerCase();
  // The authority is checked in its written form: the URL parser would normalise a dotted-decimal or hex host.
  const authority = match[2]!;
  const hostPort = /^(\[[0-9a-f:.]+\]|[^:]+)(?::(\d{1,5}))?$/i.exec(authority);
  if (!hostPort) throw refuse("src has an invalid host.");
  const host = hostPort[1]!.toLowerCase();
  const port = hostPort[2] === undefined ? undefined : Number(hostPort[2]);
  if (port !== undefined && (port < 1 || port > 65535)) throw refuse("src has an invalid port.");

  if (scheme === "http") {
    if (!options.allowLoopback || !LOOPBACK.test(host)) throw refuse("src must use https (http is for a loopback host in a local resolver only).");
  } else {
    if (IPV4.test(host) || host.startsWith("[")) throw refuse("src must name a domain, not an IP address.");
    let ascii: string;
    try { ascii = new URL(`https://${host}`).hostname; } catch { throw refuse("src has an invalid host."); }
    if (!DOMAIN.test(ascii)) throw refuse("src must name a fully qualified domain.");
    return location(scheme, ascii, port, match[3]!);
  }
  return location(scheme, host, port, match[3]!);
}

function location(scheme: string, host: string, port: number | undefined, path: string): WebLocation {
  const trimmed = path.replace(/\/+$/, "");
  const segments = trimmed ? trimmed.slice(1).split("/") : [];
  for (const segment of segments) {
    let decoded: string;
    try { decoded = decodeURIComponent(segment); } catch { throw refuse("src has an invalid path."); }
    // Checked after decoding: %2E%2E, %2F, %5C and %00 would otherwise pass unnoticed.
    if (!decoded || decoded === "." || decoded === ".." || /[\\/\0]/.test(decoded) || decoded.trim() !== decoded) throw refuse("src has an invalid path segment.");
  }
  return { origin: `${scheme}://${host}${port === undefined ? "" : `:${port}`}`, host, port, segments };
}

/** The URL of `did.jsonl` for a web location (no path: `/.well-known/did.jsonl`). */
export function logUrlOf(src: string, options: SrcOptions = {}): string {
  const where = parseWebLocation(src, options);
  return where.segments.length ? `${where.origin}/${where.segments.join("/")}/did.jsonl` : `${where.origin}/.well-known/did.jsonl`;
}

export type FetchLogOptions = SrcOptions & { fetch?: typeof fetch; maxBytes?: number };

/** Fetch and parse the log at a web location. Nothing here is trusted: resolveVhLog verifies it. */
export async function fetchVhLog(src: string, options: FetchLogOptions = {}): Promise<{ log: VhLogEntry[]; url: string }> {
  const url = logUrlOf(src, options);
  const maxBytes = options.maxBytes ?? 4 * 1024 * 1024;
  const doFetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
  let response: Response;
  try { response = await doFetch(url, { redirect: "error", cache: "no-store", headers: { accept: "text/jsonl, application/jsonl, text/plain, */*" } }); }
  catch (cause) { throw new VhResolutionError("notFound", `Could not fetch ${url}: ${(cause as Error).message}`); }
  if (response.status === 404) throw new VhResolutionError("notFound", `No DID log at ${url}.`);
  if (!response.ok) throw new VhResolutionError("notFound", `Fetching ${url} failed (${response.status}).`);
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) throw new VhResolutionError("invalidLog", `The log at ${url} is larger than ${maxBytes} bytes.`);
  const text = await response.text();
  if (text.length > maxBytes) throw new VhResolutionError("invalidLog", `The log at ${url} is larger than ${maxBytes} bytes.`);
  try { return { log: parseVhLog(text), url }; } catch (cause) { throw new VhResolutionError("invalidLog", (cause as Error).message); }
}
