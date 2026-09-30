/**
 * Client for the did:webvh Hosting Protocol (SPEC-webvh-hosting.md). Works
 * against any conforming server: every URL is derived from the DID, nothing
 * here knows about did.md.
 */
import { didToLogUrl, parseDid } from "./url.ts";
import { createDataIntegrityProof } from "./proof.ts";
import type { Ed25519Key } from "./signer.ts";

export class HostingError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
    this.name = "HostingError";
  }
}

/** `https://<host>/.well-known/did-hosting.json` (all members optional but `protocol`). */
export type HostingCapabilities = {
  protocol: string; writes?: boolean; delete?: boolean; witness?: boolean; maxLogBytes?: number;
};

export type PutResult = { created: boolean };

export class WebvhHostingClient {
  private readonly doFetch: typeof fetch;

  constructor(options: { fetch?: typeof fetch } = {}) {
    // Late-bound so tests can swap globalThis.fetch after construction.
    this.doFetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
  }

  /** `<base>` of a DID, ending in `/`: where its resources live. */
  baseUrl(did: string): string {
    return didToLogUrl(did).replace(/did\.jsonl$/, "");
  }

  private async fail(response: Response, what: string): Promise<never> {
    const body = (await response.text().catch(() => "")).trim();
    throw new HostingError(response.status, body || `${what} failed (${response.status})`);
  }

  /** The published log text, or null when nothing is published (404). */
  async read(did: string): Promise<string | null> {
    const response = await this.doFetch(`${this.baseUrl(did)}did.jsonl?_=${Date.now()}`, { cache: "no-store" });
    if (response.status === 404) return null;
    if (!response.ok) await this.fail(response, "Reading the DID log");
    return response.text();
  }

  /** `PUT did.jsonl`: publish a new log or replace one (which must extend the old). */
  async publish(did: string, logText: string): Promise<PutResult> {
    const response = await this.doFetch(`${this.baseUrl(did)}did.jsonl`, { method: "PUT", headers: { "content-type": "text/jsonl" }, body: logText });
    if (!response.ok) await this.fail(response, "Publishing the DID log");
    return { created: response.status === 201 };
  }

  /** `POST did.jsonl`: append one or more entries (each line `\n`-terminated). */
  async append(did: string, entriesText: string): Promise<void> {
    const response = await this.doFetch(`${this.baseUrl(did)}did.jsonl`, { method: "POST", headers: { "content-type": "text/jsonl" }, body: entriesText });
    if (!response.ok) await this.fail(response, "Appending to the DID log");
  }

  /** `PUT did-witness.json`. */
  async putWitnessFile(did: string, witnessJson: string): Promise<void> {
    const response = await this.doFetch(`${this.baseUrl(did)}did-witness.json`, { method: "PUT", headers: { "content-type": "application/json" }, body: witnessJson });
    if (!response.ok) await this.fail(response, "Publishing the witness file");
  }

  /**
   * `DELETE did.jsonl` with a disconnect request signed by a current update
   * key. Returns false when nothing was published (already gone).
   */
  async remove(did: string, signKey: Ed25519Key): Promise<boolean> {
    const document = { did };
    const proof = await createDataIntegrityProof(document, {
      privateKey: signKey.privateKey,
      verificationMethod: `did:key:${signKey.multikey}#${signKey.multikey}`,
      proofPurpose: "assertionMethod",
      created: new Date().toISOString(),
    });
    const response = await this.doFetch(`${this.baseUrl(did)}did.jsonl`, {
      method: "DELETE", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...document, proof }),
    });
    if (response.status === 404) return false;
    if (!response.ok) await this.fail(response, "Removing the DID log");
    return true;
  }

  /** The host's capability document, or null if it does not serve one. */
  async capabilities(host: string): Promise<HostingCapabilities | null> {
    try {
      const response = await this.doFetch(`https://${host}/.well-known/did-hosting.json`, { cache: "no-store" });
      if (!response.ok) return null;
      const body = await response.json();
      return body && typeof body === "object" && typeof body.protocol === "string" && body.protocol.startsWith("webvh-hosting/") ? body : null;
    } catch { return null; }
  }

  /**
   * Can this location host a DID, and is it free? `declared` says whether the
   * host advertises the protocol (unknown hosts may still work).
   */
  async probe(host: string, options: { capabilities?: boolean } = {}): Promise<{ declared: boolean; capabilities: HostingCapabilities | null; available: boolean | undefined }> {
    // The SCID is irrelevant for the URL; a well-formed placeholder is enough.
    const did = `did:webvh:${"Q".repeat(46)}:${host}`;
    parseDid(did);
    // One request when only availability matters (each request costs the host).
    const capabilities = options.capabilities === false ? null : await this.capabilities(host);
    let available: boolean | undefined;
    try {
      const response = await this.doFetch(`${this.baseUrl(did)}did.jsonl?_=${Date.now()}`, { cache: "no-store" });
      available = response.status === 404 ? true : response.ok ? false : undefined;
    } catch { available = undefined; }
    return { declared: capabilities !== null, capabilities, available };
  }
}
