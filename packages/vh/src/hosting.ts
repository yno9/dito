/**
 * The client side of the did:vh Hosting Protocol (SPEC-vh-hosting.md). The URLs
 * come from a web location (`src`, see src.ts), not from the DID, which names
 * none; the verbs are PUT/POST/DELETE/GET on `did.jsonl` (§3) and
 * `GET /log?scid=` (§11).
 */
import { createDataIntegrityProof } from "./proof.ts";
import type { Ed25519Key } from "./signer.ts";
import { logUrlOf, parseWebLocation, type SrcOptions } from "./src.ts";

export class HostingError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "HostingError";
  }
}

/**
 * `url` with a query that no cache has seen. A host's log is cached by its CDN for 30 seconds
 * (`s-maxage`); a read that is followed by a write must not be handed a copy older than the
 * last write, or the new entry is numbered from the old log and the host refuses it
 * (`version '4' in log doesn't match expected '5'`). `cache: "no-store"` only bypasses the
 * browser's own cache.
 */
export function uncachedUrl(url: string | URL, now: number = Date.now()): string {
  const target = new URL(url);
  target.searchParams.set("_", String(now));
  return target.toString();
}

/** `https://<host>/.well-known/did-hosting.json` (all members optional but `protocol`). */
export type HostingCapabilities = { protocol: string; writes?: boolean; delete?: boolean; maxLogBytes?: number; methods?: string[] };

export class VhHostingClient {
  private readonly doFetch: typeof fetch;
  private readonly options: SrcOptions;

  constructor(options: { fetch?: typeof fetch } & SrcOptions = {}) {
    // Late-bound so tests can swap globalThis.fetch after construction.
    this.doFetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
    this.options = { allowLoopback: options.allowLoopback };
  }

  /** `<base>` of a location, ending in `/`: where its resources live. */
  baseUrl(src: string): string { return logUrlOf(src, this.options).replace(/did\.jsonl$/, ""); }

  private async fail(response: Response, what: string): Promise<never> {
    const body = (await response.text().catch(() => "")).trim();
    throw new HostingError(response.status, body || `${what} failed (${response.status})`);
  }

  /** The published log text, or null when nothing is published (404). */
  async read(src: string): Promise<string | null> {
    const response = await this.doFetch(uncachedUrl(`${this.baseUrl(src)}did.jsonl`), { cache: "no-store" });
    if (response.status === 404) return null;
    if (!response.ok) await this.fail(response, "Reading the DID log");
    return response.text();
  }

  /** `PUT did.jsonl`: publish a new log or replace one (which must extend the old). `created` is whether it was new. */
  async publish(src: string, logText: string): Promise<{ created: boolean }> {
    const response = await this.doFetch(`${this.baseUrl(src)}did.jsonl`, { method: "PUT", headers: { "content-type": "text/jsonl" }, body: logText });
    if (!response.ok) await this.fail(response, "Publishing the DID log");
    return { created: response.status === 201 };
  }

  /** `POST did.jsonl`: append one or more entries (each line `\n`-terminated). */
  async append(src: string, entriesText: string): Promise<void> {
    const response = await this.doFetch(`${this.baseUrl(src)}did.jsonl`, { method: "POST", headers: { "content-type": "text/jsonl" }, body: entriesText });
    if (!response.ok) await this.fail(response, "Appending to the DID log");
  }

  /**
   * `DELETE did.jsonl` with a disconnect request signed by a current update key
   * of the log the host holds. False when nothing was published (already gone).
   * This takes the log down from this host; it does not deactivate the DID.
   */
  async remove(src: string, did: string, signKey: Ed25519Key): Promise<boolean> {
    const document = { did };
    const proof = await createDataIntegrityProof(document, {
      privateKey: signKey.privateKey, verificationMethod: `did:key:${signKey.multikey}#${signKey.multikey}`, proofPurpose: "assertionMethod", created: new Date().toISOString(),
    });
    const response = await this.doFetch(`${this.baseUrl(src)}did.jsonl`, { method: "DELETE", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...document, proof }) });
    if (response.status === 404) return false;
    if (!response.ok) await this.fail(response, "Removing the DID log");
    return true;
  }

  /** `GET <watcher>/log?scid=` (a host's watcher read API): the log text, or null when unknown. */
  async readByScid(watcher: string, scid: string): Promise<string | null> {
    const where = parseWebLocation(watcher, this.options);
    const response = await this.doFetch(uncachedUrl(`${where.origin}/log?scid=${encodeURIComponent(scid)}`), { cache: "no-store" });
    if (response.status === 404) return null;
    if (!response.ok) await this.fail(response, "Reading the DID log by SCID");
    return response.text();
  }

  /** Is this location free? (`GET did.jsonl` is 404.) undefined when it cannot be told. */
  async isFree(src: string): Promise<boolean | undefined> {
    try {
      const response = await this.doFetch(uncachedUrl(`${this.baseUrl(src)}did.jsonl`), { cache: "no-store" });
      return response.status === 404 ? true : response.ok ? false : undefined;
    } catch { return undefined; }
  }

  /** The host's capability document, or null if it does not serve one. */
  async capabilities(src: string): Promise<HostingCapabilities | null> {
    try {
      const where = parseWebLocation(src, this.options);
      const response = await this.doFetch(`${where.origin}/.well-known/did-hosting.json`, { cache: "no-store" });
      if (!response.ok) return null;
      const body = await response.json();
      return body && typeof body === "object" && typeof body.protocol === "string" && body.protocol.startsWith("vh-hosting/") ? body : null;
    } catch { return null; }
  }

  /**
   * Can this location host a DID, and is it free? `declared` says whether the host advertises the protocol (unknown hosts may
   * still work). One request when only availability matters (each request costs the host).
   */
  async probe(src: string, options: { capabilities?: boolean } = {}): Promise<{ declared: boolean; capabilities: HostingCapabilities | null; available: boolean | undefined }> {
    const capabilities = options.capabilities === false ? null : await this.capabilities(src);
    return { declared: capabilities !== null, capabilities, available: await this.isFree(src) };
  }

  /** Does the host at `src` speak the protocol? (A capability document that names it.) */
  async publishesVh(src: string): Promise<boolean> {
    return (await this.capabilities(src)) !== null;
  }
}
