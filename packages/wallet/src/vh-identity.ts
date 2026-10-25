/**
 * A dito identity whose DID is `did:vh:<SCID>`: the counterpart of `Identity`
 * (identity.ts, did:webvh) with the same keys and the same life, in the same
 * DOM-free shape.
 *
 * The keys are the same profile: one 24-word mnemonic, a Root key at m/0', and
 * permanent pre-rotation (every entry is signed by the Spare the entry before
 * committed to and commits the next one; `entries.length - 1` is the Spare that
 * signs the next entry). What differs is the DID and the log:
 *
 *  - the DID names no host, so an identity can be created with none, and given
 *    one later by a single update entry (no provisional `…:ex.alias` DID, no
 *    `portable` move: the DID never changes);
 *  - the log is handled by packages/vh (didwebvh-ts refuses a `state.id` that
 *    is not a did:webvh);
 *  - where it is published is said in the document itself (`alsoKnownAs`:
 *    the location's did:web DID and a `did:vh:<SCID>?src=<location>` alias),
 *    which is also what a host checks before it stores the log.
 */
import {
  VhHostingClient, applyParameters, keyHash, locationsOf, parseVhLog, resolveVhLog, serializeVhLog, updateVhLog, createVhLog, withLocation,
  type ActiveParameters, type Location, type VhLogEntry,
} from "../../vh/src/index.ts";
import { createIdentityMaterial, mnemonicForSeed, rootFromMasterSeed, seedFromMnemonic, spareFromMasterSeed, type ControllerKey } from "./did-webvh.ts";
import { openIdentityContainer, sealIdentityContainer } from "./identity-container.ts";

type DidDocument = Record<string, any>;

/** A prepared-but-unpublished next log state. */
export type VhStep = { entries: VhLogEntry[]; entry: VhLogEntry; nextSpareIndex: number };

export type VhPublishResult = { did: string; src: string; logUrl: string; versionId: string; verifiedLive: boolean };

function activeParameters(entries: ReadonlyArray<VhLogEntry>): ActiveParameters {
  let active: ActiveParameters | undefined;
  entries.forEach((entry, index) => { active = applyParameters(active, entry.parameters, index === 0); });
  return active!;
}

/** `https://<username>.<domain>`, or `https://<domain>` without a username. */
export function locationFor(target: { username?: string; domain?: string }): string {
  const domain = (target.domain ?? "did.md").trim().toLowerCase();
  if (target.username !== undefined && !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(target.username)) throw new Error("Username must be a lowercase DNS-label-like identifier.");
  return `https://${target.username ? `${target.username}.` : ""}${domain}`;
}

/**
 * Validates `entries` (the whole did:vh log) and that `masterSeed` really owns it: genesis Root key,
 * published Root key, the current pre-rotation commitment, the current Sign key.
 */
export async function verifyMasterOwnsVhLog(entries: VhLogEntry[], masterSeed: Uint8Array): Promise<{ root: ControllerKey; sign: ControllerKey; currentSpareIndex: number }> {
  const did = entries[0]?.state?.id;
  if (typeof did !== "string") throw new Error("The DID log has no DID.");
  await resolveVhLog(did, entries);
  const parameters = activeParameters(entries);
  if (parameters.nextKeyHashes.length !== 1) throw new Error("This identity does not satisfy permanent pre-rotation invariants.");
  const root = await rootFromMasterSeed(masterSeed);
  if (!entries[0]!.parameters.updateKeys?.includes(root.multikey)) throw new Error("This Passphrase does not match the identity's genesis Root Key.");
  const methods = (entries.at(-1)!.state as DidDocument).verificationMethod;
  if (!Array.isArray(methods) || !methods.some((method: any) => method?.publicKeyMultibase === root.multikey)) throw new Error("The Master-derived Root Key is missing from the DID Document.");
  const currentSpareIndex = entries.length - 1;
  const nextSpare = await spareFromMasterSeed(masterSeed, currentSpareIndex);
  if (!parameters.nextKeyHashes.includes(keyHash(nextSpare.multikey))) throw new Error("This Passphrase does not match the current pre-rotation commitment.");
  const sign = entries.length === 1 ? root : await spareFromMasterSeed(masterSeed, currentSpareIndex - 1);
  if (!parameters.updateKeys.includes(sign.multikey)) throw new Error("The DID log's current Sign Key does not match this Master-derived key sequence.");
  return { root, sign, currentSpareIndex };
}

export class VhIdentity {
  private masterSeed: Uint8Array;
  private _root: ControllerKey;
  private _sign: ControllerKey;
  private _spareIndex: number;
  private _entries: VhLogEntry[];
  private readonly client: VhHostingClient;

  private constructor(masterSeed: Uint8Array, root: ControllerKey, sign: ControllerKey, spareIndex: number, entries: VhLogEntry[], client: VhHostingClient) {
    this.masterSeed = masterSeed;
    this._root = root;
    this._sign = sign;
    this._spareIndex = spareIndex;
    this._entries = entries;
    this.client = client;
  }

  /**
   * A fresh identity. With a `location` it is born published-to-be at that address (its document already names it); without
   * one it has no host yet and `connect` gives it one.
   */
  static async create(options: { api?: string; displayName?: string; location?: { username?: string; domain?: string }; fetch?: typeof fetch } = {}): Promise<{ identity: VhIdentity; mnemonic: string }> {
    const material = await createIdentityMaterial();
    const src = options.location ? locationFor(options.location) : undefined;
    const created = await createVhLog({
      signer: material.sign, updateKeys: [material.sign.multikey], nextKeyHashes: [keyHash(material.nextSpare.multikey)],
      document: did => {
        const document = {
          "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
          id: did,
          // Relative, like the did:webvh genesis: the reference does not depend on the DID string.
          verificationMethod: [{ id: "#pass-1", type: "Multikey", controller: did, publicKeyMultibase: material.root.multikey }],
          authentication: ["#pass-1"],
          // SIOPv2 wallet discovery: where this identity's authorization screen is.
          service: options.api ? [{ id: "#wallet", type: "SelfIssuedOPAuthorizationEndpoint", serviceEndpoint: options.api }] : [],
          ...(options.displayName ? { name: options.displayName } : {}),
        };
        return src ? withLocation(document, did, src) : document;
      },
    });
    const identity = new VhIdentity(material.masterSeed, material.root, material.sign, material.nextSpareIndex, created.log, new VhHostingClient({ fetch: options.fetch }));
    return { identity, mnemonic: material.masterMnemonic };
  }

  /** Open an identity from its mnemonic and log; verifies the log and that this mnemonic owns it. */
  static async open(options: { mnemonic?: string; masterSeed?: Uint8Array; log: string | VhLogEntry[]; fetch?: typeof fetch }): Promise<VhIdentity> {
    const masterSeed = options.masterSeed ?? (options.mnemonic ? seedFromMnemonic(options.mnemonic, "Passphrase") : undefined);
    if (!masterSeed) throw new Error("A mnemonic or master seed is required.");
    const entries = typeof options.log === "string" ? parseVhLog(options.log) : options.log;
    const { root, sign, currentSpareIndex } = await verifyMasterOwnsVhLog(entries, masterSeed);
    return new VhIdentity(masterSeed, root, sign, currentSpareIndex, entries, new VhHostingClient({ fetch: options.fetch }));
  }

  /**
   * Open an identity whose log is published somewhere (a new device): from a web location (`src`), or by SCID from a host's
   * watcher API (`GET <watcher>/log?scid=`; any host name serves it). The DID alone names neither.
   */
  static async fromSource(options: { mnemonic?: string; masterSeed?: Uint8Array; src?: string; watcher?: string; scid?: string; fetch?: typeof fetch }): Promise<VhIdentity> {
    const client = new VhHostingClient({ fetch: options.fetch });
    let text: string | null;
    if (options.src) text = await client.read(options.src);
    else if (options.watcher && options.scid) text = await client.readByScid(options.watcher, options.scid);
    else throw new Error("A src, or a watcher and a SCID, is required.");
    if (text === null) throw new Error("Could not find the DID log.");
    return VhIdentity.open({ mnemonic: options.mnemonic, masterSeed: options.masterSeed, log: text, fetch: options.fetch });
  }

  get entries(): readonly VhLogEntry[] { return this._entries; }
  get did(): string { return this._entries[0]!.state.id as string; }
  get state(): DidDocument { return this._entries.at(-1)!.state as DidDocument; }
  get scid(): string { return this._entries[0]!.parameters.scid as string; }
  get parameters(): ActiveParameters { return activeParameters(this._entries); }
  /** The locations the current document says the log is published at (the first is where updates go). */
  get locations(): Location[] { return locationsOf(this.did, this.state); }
  /** True until the identity has a location. */
  get isProvisional(): boolean { return this.locations.length === 0; }
  /** The recovery secret. Handle with care. */
  get mnemonic(): string { return mnemonicForSeed(this.masterSeed); }
  logText(): string { return serializeVhLog(this._entries); }

  /** The identity as one portable `<scid>.jwe` (log + Master keyring), wrapped by the mnemonic itself. */
  async exportContainer(): Promise<{ scid: string; jwe: string }> {
    const latest = this._entries.at(-1)!;
    const jwe = await sealIdentityContainer({ scid: this.scid, did: this.did, rootKey: this._root.multikey, generation: latest.versionId, didJsonl: this.logText(), masterSeed: this.masterSeed });
    return { scid: this.scid, jwe };
  }

  static async fromContainer(options: { jwe: string; mnemonic: string; fetch?: typeof fetch }): Promise<VhIdentity> {
    const masterSeed = seedFromMnemonic(options.mnemonic, "Passphrase");
    const container = await openIdentityContainer(options.jwe, masterSeed);
    const identity = await VhIdentity.open({ masterSeed, log: container.didJsonl, fetch: options.fetch });
    if (identity.did !== container.did || identity.entries.at(-1)!.versionId !== container.generation) throw new Error("The container's DID log does not match its manifest.");
    return identity;
  }

  // ---- offline steps: prepare (pure) then commit (advance local state) ----

  /** The next entry, with a complete new DID Document, signed by the committed Spare and committing the next one. */
  async prepareUpdate(state: DidDocument): Promise<VhStep> {
    const spare = await spareFromMasterSeed(this.masterSeed, this._spareIndex);
    const nextSpare = await spareFromMasterSeed(this.masterSeed, this._spareIndex + 1);
    const { log } = await updateVhLog({
      log: this._entries, signer: spare, document: state,
      parameters: { updateKeys: [spare.multikey], nextKeyHashes: [keyHash(nextSpare.multikey)] },
    });
    return { entries: log, entry: log.at(-1)!, nextSpareIndex: this._spareIndex + 1 };
  }

  /** Adopt a prepared step (after the host accepted it, or for offline use). */
  async commit(step: VhStep): Promise<void> {
    if (step.entries.length !== this._entries.length + 1) throw new Error("This step does not extend the current log.");
    this._sign = await spareFromMasterSeed(this.masterSeed, this._spareIndex);
    this._spareIndex = step.nextSpareIndex;
    this._entries = step.entries;
  }

  // ---- publishing ----

  /**
   * A document change (or a plain key rotation when `edit` is omitted): published to the first location, then local state
   * advances. With no location it only advances locally. An edit that stops naming the location is refused here, as the
   * host would refuse it.
   */
  async publishUpdate(edit?: (state: DidDocument) => DidDocument | void): Promise<VhPublishResult | undefined> {
    const draft = JSON.parse(JSON.stringify(this.state)) as DidDocument;
    const state = (edit ? edit(draft) : undefined) ?? draft;
    const here = this.locations[0];
    if (here && !locationsOf(this.did, state).some(location => location.src === here.src) ) throw new Error(`The edited document no longer names ${here.didWeb} and its ?src= alias; the host would refuse it.`);
    if (here && !(Array.isArray(state.alsoKnownAs) && state.alsoKnownAs.includes(here.didWeb))) throw new Error(`The edited document no longer names ${here.didWeb}; the host would refuse it.`);
    const step = await this.prepareUpdate(state);
    if (!here) { await this.commit(step); return undefined; }
    await this.client.append(here.src, `${JSON.stringify(step.entry)}\n`);
    await this.commit(step);
    return this.resultAt(here.src);
  }

  /** PUT the whole log to the first location: the first publication of an identity that was created with one, or a republish. */
  async publish(): Promise<VhPublishResult> {
    const here = this.locations[0];
    if (!here) throw new Error("This identity has no location; connect it to a host first.");
    await this.client.publish(here.src, this.logText());
    return this.resultAt(here.src);
  }

  /** Rotate the Sign key (a new pre-rotated entry, same document). */
  rotate(): Promise<VhPublishResult | undefined> { return this.publishUpdate(); }

  /**
   * Give the identity a location (`<username>.<domain>`, default did.md) and publish the full log there. One entry: the
   * document starts to name the place (and stops naming the old one, if it had one); the DID stays what it was. The old copy
   * is taken down on a best-effort basis (`cleanupError` reports a failure).
   */
  async connect(target: { username?: string; domain?: string }): Promise<VhPublishResult & { cleanupError?: Error }> {
    const src = locationFor(target);
    const old = this.locations[0];
    if (old?.src === src) throw new Error("This identity is already at that location.");
    if (!await this.client.publishesVh(src)) throw new Error(`${new URL(src).host} does not publish did:vh.`);
    const step = await this.prepareUpdate(withLocation(this.state, this.did, src, old?.src));
    await this.client.publish(src, serializeVhLog(step.entries));
    const previous = { sign: this._sign };
    await this.commit(step);
    const result = await this.resultAt(src);
    if (!old) return result;
    try { await this.client.remove(old.src, this.did, previous.sign); return result; }
    catch (error) { return { ...result, cleanupError: error instanceof Error ? error : new Error(String(error)) }; }
  }

  /** Take the log down from its first location (a signed DELETE). It does not deactivate the DID. */
  async unpublish(): Promise<void> {
    const here = this.locations[0];
    if (!here) throw new Error("This identity has no location.");
    await this.client.remove(here.src, this.did, this._sign);
  }

  /** True if the first location serves the newest version right now. */
  async isLive(): Promise<boolean> {
    const here = this.locations[0];
    if (!here) return false;
    try { return (await this.client.read(here.src)) === this.logText(); } catch { return false; }
  }

  /** Scrub key material. The object is unusable afterwards. */
  destroy(): void {
    this.masterSeed.fill(0);
    this._root.privateKey.fill(0);
    this._sign.privateKey.fill(0);
  }

  private async resultAt(src: string): Promise<VhPublishResult> {
    const versionId = this._entries.at(-1)!.versionId;
    const live = await this.client.read(src).catch(() => null);
    return { did: this.did, src, logUrl: `${this.client.baseUrl(src)}did.jsonl`, versionId, verifiedLive: live === this.logText() };
  }
}

