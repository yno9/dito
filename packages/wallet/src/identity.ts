/**
 * A dito identity as a plain, DOM-free object: everything the dashboard does
 * to a did:webvh log, callable from a script, a CLI or an agent.
 *
 * The whole identity is a function of two things -- the 24-word mnemonic (the
 * only secret) and the public log -- so there is nothing to persist except
 * the log; callers keep the mnemonic wherever suits them (a prompt, an env
 * var, a password manager). Nothing here reads or writes storage.
 *
 * Publishing goes through an IdentityHost adapter (did.md, GitHub Pages), and
 * local state only advances once the host accepted the write.
 */
import { currentParameters, didToLogUrl, fetchWitnessProofs, nextKeyHash, parseLog, resolveLog, serializeLog, usesWitnesses } from "../../webvh/src/index.ts";
import {
  buildGenesis,
  createIdentityMaterial,
  mnemonicForSeed,
  preparePortableImport,
  preparePreRotatedUpdate,
  rootFromMasterSeed,
  seedFromMnemonic,
  spareFromMasterSeed,
  type ControllerKey,
} from "./did-webvh.ts";
import { hostForDid, isProvisionalHostlessDid, type IdentityHost, type PublishResult } from "./host.ts";
import { githubDidLocation, publishToGitHub, verifyToken, type PublishProgress } from "./github-host.ts";
import type { Entry } from "./webvh-core.ts";

type DidDocument = Record<string, any>;

/** A prepared-but-unpublished next log state (see Identity.prepare*). */
export type PreparedStep = {
  entries: Entry[];
  entry: Entry;
  nextSpareIndex: number;
  /** DID before the step, when it changes the DID (a location move). */
  previousDid?: string;
};

type WitnessProofs = NonNullable<Parameters<typeof resolveLog>[1]> extends { witnessProofs?: infer W } ? NonNullable<W> : never;

export type OpenOptions = {
  /** The 24-word mnemonic (or the 32-byte seed it encodes). */
  mnemonic?: string;
  masterSeed?: Uint8Array;
  /** The DID log: `did.jsonl` text or parsed entries. */
  log: string | Entry[];
  /** `did-witness.json` entries, for a log that configures witnesses. */
  witnessProofs?: WitnessProofs;
};

/**
 * Validates `entries` (the whole did:webvh chain, via didwebvh-ts) and that
 * `masterSeed` really owns the log: genesis root key, published root key,
 * current pre-rotation commitment, current sign key. Returns the derived keys.
 */
export async function verifyMasterOwnsLog(entries: Entry[], masterSeed: Uint8Array, witnessProofs?: WitnessProofs): Promise<{ root: ControllerKey; sign: ControllerKey; currentSpareIndex: number }> {
  await resolveLog(entries as never, witnessProofs ? { witnessProofs } : {});
  const parameters = currentParameters(entries as never) as any;
  if (!Array.isArray(parameters.nextKeyHashes) || parameters.nextKeyHashes.length !== 1) {
    throw new Error("This identity does not satisfy permanent pre-rotation invariants.");
  }
  const root = await rootFromMasterSeed(masterSeed);
  if (!(entries[0]!.parameters as any).updateKeys?.includes(root.multikey)) {
    throw new Error("This Passphrase does not match the identity's genesis Root Key.");
  }
  const methods = (entries.at(-1)!.state as any).verificationMethod;
  if (!Array.isArray(methods) || !methods.some((method: any) => method?.publicKeyMultibase === root.multikey)) {
    throw new Error("The Master-derived Root Key is missing from the DID Document.");
  }
  const currentSpareIndex = entries.length - 1;
  const nextSpare = await spareFromMasterSeed(masterSeed, currentSpareIndex);
  if (!parameters.nextKeyHashes.includes(await nextKeyHash(nextSpare.multikey))) {
    throw new Error("This Passphrase does not match the current pre-rotation commitment.");
  }
  const sign = entries.length === 1 ? root : await spareFromMasterSeed(masterSeed, currentSpareIndex - 1);
  if (!parameters.updateKeys?.includes(sign.multikey)) {
    throw new Error("The DID log's current Sign Key does not match this Master-derived key sequence.");
  }
  return { root, sign, currentSpareIndex };
}

export class Identity {
  private constructor(
    private masterSeed: Uint8Array,
    private _root: ControllerKey,
    private _sign: ControllerKey,
    private _spareIndex: number,
    private _entries: Entry[],
  ) {}

  /** A fresh identity: provisional DID (`…:ex.alias`), no host yet. */
  static async create(options: { api?: string; displayName?: string } = {}): Promise<{ identity: Identity; mnemonic: string }> {
    const material = await createIdentityMaterial();
    const genesis = await buildGenesis({
      username: "ex", domain: "alias", root: material.root, sign: material.sign, nextSpare: material.nextSpare,
      api: options.api, displayName: options.displayName,
    });
    const identity = new Identity(material.masterSeed, material.root, material.sign, material.nextSpareIndex, [genesis]);
    return { identity, mnemonic: material.masterMnemonic };
  }

  /**
   * Open an identity from its mnemonic and log. Verifies that the log is valid
   * and that this mnemonic really owns it (genesis root key, published root
   * key, current pre-rotation commitment, current sign key).
   */
  static async open(options: OpenOptions): Promise<Identity> {
    const masterSeed = options.masterSeed ?? (options.mnemonic ? seedFromMnemonic(options.mnemonic, "Passphrase") : undefined);
    if (!masterSeed) throw new Error("A mnemonic or master seed is required.");
    const entries = (typeof options.log === "string" ? parseLog(options.log) : options.log) as unknown as Entry[];
    const { root, sign, currentSpareIndex: spareIndex } = await verifyMasterOwnsLog(entries, masterSeed, options.witnessProofs);
    return new Identity(masterSeed, root, sign, spareIndex, entries);
  }

  /**
   * Open an identity whose public log is served at its DID (e.g. on a new
   * device): fetches `did.jsonl` (and `did-witness.json` when the log uses
   * witnesses) from the location the DID names.
   */
  static async fromDid(options: { did: string; mnemonic?: string; masterSeed?: Uint8Array; fetch?: typeof fetch }): Promise<Identity> {
    const doFetch = options.fetch ?? fetch;
    const logUrl = didToLogUrl(options.did);
    const response = await doFetch(logUrl, { cache: "no-store" });
    if (!response.ok) throw new Error(`Could not fetch the DID log (${response.status}).`);
    const log = parseLog(await response.text());
    const witnessProofs = usesWitnesses(log) ? await fetchWitnessProofs(logUrl, doFetch) : undefined;
    return Identity.open({ mnemonic: options.mnemonic, masterSeed: options.masterSeed, log: log as unknown as Entry[], witnessProofs });
  }

  get entries(): readonly Entry[] { return this._entries; }
  get did(): string { return this._entries.at(-1)!.state.id as string; }
  get state(): DidDocument { return this._entries.at(-1)!.state as DidDocument; }
  get scid(): string { return (this._entries[0]!.parameters as any).scid; }
  get parameters() { return currentParameters(this._entries as never); }
  /** True until the identity has been given a real location. */
  get isProvisional(): boolean { return isProvisionalHostlessDid(this.did); }
  get host(): IdentityHost { return hostForDid(this.did); }
  /** The recovery secret. Handle with care. */
  get mnemonic(): string { return mnemonicForSeed(this.masterSeed); }
  /** The public log as `did.jsonl` text. */
  logText(): string { return serializeLog(this._entries as never); }

  // ---- offline steps: prepare (pure) then commit (advance local state) ----

  /** Next entry with a complete new DID Document (optionally moving location). */
  async prepareUpdate(state: DidDocument, options: { domain?: string } = {}): Promise<PreparedStep> {
    const prepared = await preparePreRotatedUpdate({
      entries: this._entries, state, masterSeed: this.masterSeed, currentSpareIndex: this._spareIndex, domain: options.domain,
    });
    return { entries: [...this._entries, prepared.entry], entry: prepared.entry, nextSpareIndex: prepared.nextSpareIndex };
  }

  /** The portability entry that gives this identity `<username>.<domain>`. */
  async prepareMove(target: { username: string; domain: string }): Promise<PreparedStep> {
    const moved = await preparePortableImport({ entries: this._entries, ...target, masterSeed: this.masterSeed });
    return { entries: [...this._entries, moved.entry], entry: moved.entry, nextSpareIndex: moved.nextSpareIndex, previousDid: this.did };
  }

  /** Adopt a prepared step (after the host accepted it, or for offline use). */
  async commit(step: PreparedStep): Promise<void> {
    if (step.entries.length !== this._entries.length + 1) throw new Error("This step does not extend the current log.");
    this._sign = await spareFromMasterSeed(this.masterSeed, this._spareIndex);
    this._spareIndex = step.nextSpareIndex;
    this._entries = step.entries;
  }

  // ---- publishing ----

  /**
   * Publish a document change (or a plain key rotation when `edit` is
   * omitted) to the DID's current host, then advance local state.
   */
  async publishUpdate(edit?: (state: DidDocument) => DidDocument | void, options: { credential?: string } = {}): Promise<PublishResult> {
    const draft = JSON.parse(JSON.stringify(this.state)) as DidDocument;
    const state = (edit ? edit(draft) : undefined) ?? draft;
    const step = await this.prepareUpdate(state);
    const result = await this.host.publish({ entries: step.entries, mode: "append", credential: options.credential, message: `Publish update ${step.entry.versionId}` });
    await this.commit(step);
    return result;
  }

  /** Rotate the Sign key (a new pre-rotated entry, same document). */
  rotate(options: { credential?: string } = {}): Promise<PublishResult> {
    return this.publishUpdate(undefined, options);
  }

  /**
   * Give the identity a did.md (or other HTTP host) location and publish the
   * full log there. When it was hosted elsewhere, the old copy is removed on a
   * best-effort basis (`cleanupError` reports a failure).
   */
  async connect(target: { username: string; domain?: string }): Promise<PublishResult & { cleanupError?: Error }> {
    const step = await this.prepareMove({ username: target.username, domain: target.domain ?? "did.md" });
    const newDid = step.entry.state.id as string;
    const result = await hostForDid(newDid).publish({ entries: step.entries, mode: "replace", message: `Publish ${step.entry.versionId}` });
    const previous = { did: this.did, sign: this._sign };
    await this.commit(step);
    return { ...result, ...(await this.removeOld(previous.did, previous.sign)) };
  }

  /** Host on `<login>.github.io` (login taken from the token). */
  async hostOnGitHub(options: { token: string; onProgress?: PublishProgress; timeoutMs?: number; intervalMs?: number }) {
    const { login } = await verifyToken(options.token);
    const onGitHub = githubDidLocation(login).domain === this.did.split(":").slice(3).join(":");
    const step = onGitHub ? undefined : await this.prepareMove({ username: login, domain: "github.io" });
    const entries = step ? step.entries : [...this._entries];
    const result = await publishToGitHub({
      token: options.token, entries, onProgress: options.onProgress, timeoutMs: options.timeoutMs, intervalMs: options.intervalMs,
      message: step ? `Publish did:webvh ${step.entry.versionId} (portability move)` : `Republish did:webvh ${entries.at(-1)!.versionId}`,
    });
    const previous = { did: this.did, sign: this._sign };
    if (step) await this.commit(step);
    return { ...result, ...(step ? await this.removeOld(previous.did, previous.sign) : {}) };
  }

  /** Un-host the DID (did.md: signed DELETE; GitHub: deletes only the DID files). */
  async unpublish(options: { credential?: string } = {}): Promise<void> {
    await this.host.remove(this.did, this._sign, options.credential);
  }

  /** True if the current host serves the log right now. */
  isLive(): Promise<boolean> { return this.host.isLive(this.did); }

  /** Scrub key material. The object is unusable afterwards. */
  destroy(): void {
    this.masterSeed.fill(0);
    this._root.privateKey.fill(0);
    this._sign.privateKey.fill(0);
  }

  private async removeOld(did: string, sign: ControllerKey): Promise<{ cleanupError?: Error }> {
    if (isProvisionalHostlessDid(did) || did === this.did) return {};
    try { await hostForDid(did).remove(did, sign); return {}; }
    catch (error) { return { cleanupError: error instanceof Error ? error : new Error(String(error)) }; }
  }
}
