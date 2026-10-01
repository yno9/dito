// The portable identity container (`<scid>.jwe`): one JWE (see wallet-backup.ts)
// holding the DID log and a Master keyring. It carries no username -- the SCID
// is the identity -- so it works for any host, including a bring-your-own
// domain. The browser wallet writes and reads the same format (version 3);
// versions 1-2 (username-keyed) remain readable there and here.
import { decryptIdentityContainer, encryptIdentityContainer } from "./wallet-backup.ts";

const FORMAT = "did.md/identity-container";
const PROFILE = "did.md/master-ed25519-v1";

function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

export function containerPath(scid: string, name: string): string {
  return `identities/${scid}/${name}`;
}

export async function sealIdentityContainer(args: { scid: string; did: string; rootKey: string; generation: string; didJsonl: string; masterSeed: Uint8Array }): Promise<string> {
  const didLogPath = containerPath(args.scid, "did.jsonl");
  const keyringPath = containerPath(args.scid, "keyring.json");
  const files = {
    [didLogPath]: args.didJsonl,
    [keyringPath]: { type: "bip39-slip10-ed25519", masterEntropy: base64url(args.masterSeed), derivationProfile: PROFILE, applications: [] },
    "metadata/device-bindings.json": [],
    "metadata/grants.json": { oauth: [] },
  };
  const identity = { did: args.did, rootKey: args.rootKey, generation: args.generation, didLogPath, keyringPath, derivationProfile: PROFILE };
  return encryptIdentityContainer({
    format: FORMAT, version: 3,
    manifest: { format: FORMAT, version: 3, createdAt: new Date().toISOString(), identities: [identity], contents: Object.keys(files) },
    files,
  }, args.masterSeed);
}

/** Opens a container with its Master seed and returns the DID log text it holds (not yet verified against the seed). */
export async function openIdentityContainer(jwe: string, masterSeed: Uint8Array): Promise<{ did: string; generation: string; didJsonl: string }> {
  const value = await decryptIdentityContainer(jwe, masterSeed) as any;
  if (value?.format !== FORMAT || ![2, 3].includes(value.version) || value.manifest?.version !== value.version
    || !Array.isArray(value.manifest.identities) || value.manifest.identities.length !== 1 || !value.files || typeof value.files !== "object") {
    throw new Error("This is not a supported did.md identity container.");
  }
  const identity = value.manifest.identities[0];
  const didJsonl = value.files[identity?.didLogPath];
  if (typeof identity?.did !== "string" || typeof identity.generation !== "string" || typeof didJsonl !== "string") throw new Error("Identity container manifest is invalid.");
  const keyring = value.files[identity.keyringPath];
  if (keyring?.masterEntropy !== undefined && keyring.masterEntropy !== base64url(masterSeed)) throw new Error("The container keyring does not match this mnemonic.");
  return { did: identity.did, generation: identity.generation, didJsonl };
}
