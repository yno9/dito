/**
 * The did:vh log operations as plain functions of a log and the Master seed, for a caller that keeps its own session state
 * (the browser wallet) rather than an `Identity` object. `Identity` is the same operations behind a class.
 */
import {
  applyParameters, createVhLog, keyHash, updateVhLog, withLocation,
  type ActiveParameters, type VhLogEntry,
} from "../../vh/src/index.ts";
import { spareFromMasterSeed, type ControllerKey } from "./keys.ts";

type DidDocument = Record<string, any>;

/** The parameters in force after the last entry. */
export function currentVhParameters(entries: ReadonlyArray<VhLogEntry>): ActiveParameters {
  let active: ActiveParameters | undefined;
  entries.forEach((entry, index) => { active = applyParameters(active, entry.parameters, index === 0); });
  return active!;
}

/**
 * The genesis entry of a new identity: the Root key at `#pass-1` (authentication), the first Spare committed. With a `src`
 * (`https://alice.did.md`) the document already names that place; without one the identity has no host yet.
 */
export async function createGenesisEntry(args: {
  root: ControllerKey; sign: ControllerKey; nextSpare: ControllerKey; src?: string; displayName?: string; api?: string;
  service?: { id: string; type: string; serviceEndpoint: string }[];
}): Promise<VhLogEntry> {
  const created = await createVhLog({
    signer: args.sign, updateKeys: [args.sign.multikey], nextKeyHashes: [keyHash(args.nextSpare.multikey)],
    document: did => {
      const document: DidDocument = {
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
        id: did,
        verificationMethod: [{ id: "#pass-1", type: "Multikey", controller: did, publicKeyMultibase: args.root.multikey }],
        authentication: ["#pass-1"],
        // SIOPv2 wallet discovery: where this identity's authorization screen is.
        service: [
          ...(args.api ? [{ id: "#wallet", type: "SelfIssuedOPAuthorizationEndpoint", serviceEndpoint: args.api }] : []),
          ...(args.service ?? []),
        ],
        ...(args.displayName ? { name: args.displayName } : {}),
      };
      return args.src ? withLocation(document, did, args.src) : document;
    },
  });
  return created.log[0]!;
}

/**
 * One pre-rotated update entry, signed by the Spare the log committed to (`currentSpareIndex`), committing to the next one.
 * `state` is the complete new DID Document. The DID never changes.
 */
export async function prepareUpdateEntry(args: {
  entries: ReadonlyArray<VhLogEntry>; state: DidDocument; masterSeed: Uint8Array; currentSpareIndex: number;
}): Promise<{ entry: VhLogEntry; nextSpare: ControllerKey; nextSpareIndex: number }> {
  const parameters = currentVhParameters(args.entries);
  if (parameters.nextKeyHashes.length !== 1) throw new Error("This identity does not have exactly one active Spare Key commitment.");
  const currentSpare = await spareFromMasterSeed(args.masterSeed, args.currentSpareIndex);
  if (!parameters.nextKeyHashes.includes(keyHash(currentSpare.multikey))) throw new Error("This Passphrase does not match the public pre-rotation commitment.");
  const nextSpareIndex = args.currentSpareIndex + 1;
  const nextSpare = await spareFromMasterSeed(args.masterSeed, nextSpareIndex);
  const { log } = await updateVhLog({
    log: args.entries, signer: currentSpare, document: args.state,
    parameters: { updateKeys: [currentSpare.multikey], nextKeyHashes: [keyHash(nextSpare.multikey)] },
  });
  return { entry: log.at(-1)!, nextSpare, nextSpareIndex };
}

/** The update entry that makes the document name `src` as its place (and stop naming `previousSrc`). */
export async function prepareLocationEntry(args: {
  entries: ReadonlyArray<VhLogEntry>; src: string; previousSrc?: string; masterSeed: Uint8Array; currentSpareIndex: number;
}): Promise<{ entry: VhLogEntry; state: DidDocument; nextSpareIndex: number }> {
  const latest = args.entries.at(-1)!;
  const did = args.entries[0]!.state.id as string;
  const state = withLocation(latest.state as DidDocument, did, args.src, args.previousSrc);
  const prepared = await prepareUpdateEntry({ entries: args.entries, state, masterSeed: args.masterSeed, currentSpareIndex: args.currentSpareIndex });
  return { entry: prepared.entry, state, nextSpareIndex: prepared.nextSpareIndex };
}
