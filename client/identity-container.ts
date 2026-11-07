// The browser wallet's reading of a decrypted did.md identity container
// (packages/wallet/src/wallet-backup.ts is the JWE around it). Version 3 keys its
// files by SCID; versions 1-2 keyed them by a did.md username and stay readable so
// old exports still recover. Pure functions: no DOM, no wallet state.
import { base64urlDecode } from "../packages/vh/src/base64url.ts";
import { parseVhDid, parseVhLog } from "../packages/vh/src/index.ts";

const FORMAT = "did.md/identity-container";
const PROFILE = "did.md/master-ed25519-v1";
const USERNAME = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const MAX_LOG_CHARS = 16 * 1024 * 1024;

// Container JSON is checked field by field below; until then it is untyped.
type Json = Record<string, any>;

/** A published did:vh log: the text must end with a newline (a truncated fetch does not). */
export function parseLog(text: string) {
  if (!text.endsWith("\n")) throw new Error("Public log was not found.");
  return parseVhLog(text);
}

export function scidFromDid(did: string): string {
  try { return parseVhDid(did).scid; } catch { throw new Error("Could not derive an SCID filename from this DID."); }
}

export function containerPath(did: string, name: string): string {
  return `identities/${scidFromDid(did)}/${name}`;
}

function legacyContainerPath(username: string, name: string): string {
  return `identities/${username}/${name}`;
}

function containerString(value: unknown, label: string, maximum = 4096): string {
  if (typeof value !== "string" || !value || value.length > maximum) throw new Error(`Identity container ${label} is invalid.`);
  return value;
}

function isObject(value: unknown): value is Json {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function containerUsername(identity: Json): string {
  const username = containerString(identity.username, "username", 64);
  if (!USERNAME.test(username)) throw new Error("Identity container username is invalid.");
  return username;
}

/** The DID log a manifest entry points at, checked against that entry. */
function containerLog(files: Json, didLogPath: string, did: string, generation: string) {
  const didJsonl = files[didLogPath];
  if (typeof didJsonl !== "string" || didJsonl.length > MAX_LOG_CHARS) throw new Error("Identity container DID log is invalid.");
  const entries = parseLog(didJsonl);
  const latest = entries.at(-1) as Json | undefined;
  if (!latest?.state || latest.state.id !== did || latest.versionId !== generation) throw new Error("Identity container DID log does not match its manifest.");
  return { didJsonl, entries };
}

function containerMetadata(files: Json) {
  const deviceBindings = files["metadata/device-bindings.json"];
  const grants = files["metadata/grants.json"];
  if (!Array.isArray(deviceBindings) || !isObject(grants) || !Array.isArray(grants.oauth)
    || deviceBindings.length > 1024 || grants.oauth.length > 4096) {
    throw new Error("Identity container metadata is invalid.");
  }
  return { deviceBindings, oauth: grants.oauth };
}

/** The checked contents of a decrypted container of any supported version (1-3). */
export function checkedIdentityContainer(value: any) {
  const version = value?.version;
  if (!isObject(value) || value.format !== FORMAT || (version !== 1 && version !== 2 && version !== 3)
    || !isObject(value.manifest) || value.manifest.format !== FORMAT || value.manifest.version !== version
    || !Array.isArray(value.manifest.identities) || value.manifest.identities.length !== 1
    || !isObject(value.files)) {
    throw new Error("This is not a supported did.md identity container.");
  }
  const files = value.files;
  const metadata = containerMetadata(files);
  if (version === 1) {
    // v1's keyring was a did.md local vault record. Retained solely so users can recover existing exports.
    const identities = value.manifest.identities.map((identity: unknown) => {
      if (!isObject(identity)) throw new Error("Identity container manifest is invalid.");
      const username = containerUsername(identity);
      const did = containerString(identity.did, "DID");
      const generation = containerString(identity.generation, "generation", 512);
      const didLogPath = containerString(identity.didLogPath, "DID log path", 256);
      const keyringPath = containerString(identity.keyringPath, "keyring path", 256);
      if (didLogPath !== legacyContainerPath(username, "did.jsonl") || keyringPath !== legacyContainerPath(username, "keyring.json")) {
        throw new Error("Identity container paths are invalid.");
      }
      const { didJsonl } = containerLog(files, didLogPath, did, generation);
      return { username, did, generation, didJsonl, keyring: files[keyringPath] };
    });
    return { version: 1 as const, identities, ...metadata };
  }
  // v2+ are platform-independent: direct BIP39 entropy and the documented SLIP-0010 profile.
  const identities = value.manifest.identities.map((identity: unknown) => {
    if (!isObject(identity)) throw new Error("Identity container manifest is invalid.");
    const username = version === 2 ? containerUsername(identity) : undefined;
    const did = containerString(identity.did, "DID");
    const rootKey = containerString(identity.rootKey, "Root Key");
    const generation = containerString(identity.generation, "generation", 512);
    const didLogPath = containerString(identity.didLogPath, "DID log path", 256);
    const keyringPath = containerString(identity.keyringPath, "keyring path", 256);
    const expectedLog = username !== undefined ? legacyContainerPath(username, "did.jsonl") : containerPath(did, "did.jsonl");
    const expectedKeyring = username !== undefined ? legacyContainerPath(username, "keyring.json") : containerPath(did, "keyring.json");
    if (identity.derivationProfile !== PROFILE || didLogPath !== expectedLog || keyringPath !== expectedKeyring) {
      throw new Error("Identity container paths or derivation profile are invalid.");
    }
    const { didJsonl, entries } = containerLog(files, didLogPath, did, generation);
    const keyring = files[keyringPath];
    if (!isObject(keyring) || keyring.type !== "bip39-slip10-ed25519" || keyring.derivationProfile !== PROFILE) {
      throw new Error("Identity container keyring is invalid.");
    }
    const masterSeed = base64urlDecode(keyring.masterEntropy, "Master entropy");
    if (masterSeed.length !== 32) throw new Error("Identity container Master entropy must be 32 bytes.");
    const applications = keyring.applications === undefined ? [] : keyring.applications;
    if (!Array.isArray(applications) || applications.length > 1024) throw new Error("Identity container application metadata is invalid.");
    return { username, did, rootKey, generation, didJsonl, entries, masterSeed, applications };
  });
  return { version: version as 2 | 3, identities, ...metadata };
}
