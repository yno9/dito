/**
 * The client side of webvh-hosting/1 for did:vh logs. The URLs come from a web
 * location (`src`, see src.ts), not from the DID, which names none; the verbs
 * are the same as for a did:webvh log (SPEC-webvh-hosting.md §3), plus
 * `GET /log?scid=` (§11).
 */
import { createDataIntegrityProof } from "../../webvh/src/proof.ts";
import type { Ed25519Key } from "../../webvh/src/signer.ts";
import { uncachedUrl } from "../../webvh/src/url.ts";
import { HostingError } from "../../webvh/src/hosting.ts";
import { logUrlOf, parseWebLocation, type SrcOptions } from "./src.ts";

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

  /** Does the host at `src` publish did:vh? (`methods` in its capability document.) */
  async publishesVh(src: string): Promise<boolean> {
    try {
      const where = parseWebLocation(src, this.options);
      const response = await this.doFetch(`${where.origin}/.well-known/did-hosting.json`, { cache: "no-store" });
      if (!response.ok) return false;
      const caps = await response.json() as { methods?: unknown };
      return Array.isArray(caps.methods) && caps.methods.includes("did:vh");
    } catch { return false; }
  }
}
