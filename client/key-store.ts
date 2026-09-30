import "./browser-buffer.ts";
import { decrypt as decryptVault, encrypt as encryptVault } from "@metamask/browser-passworder";

/**
 * Browser-local metadata and optional WebAuthn-PRF sealing.
 *
 * v4 is the Passphrase format: an unprotected v4 record contains
 * metadata only. The Master is persisted only when the user explicitly
 * seals it with a passkey.
 */
export type LocalSecrets = { masterSeed: Uint8Array; signPrivateKey: Uint8Array };
export type PasskeyProtector = {
  mode: "passkey";
  key: CryptoKey;
  credentialId: number[];
  prfSalt: number[];
};
export type Unprotected = { mode: "none" };
export type Protector = PasskeyProtector | Unprotected;

export type SealedPayload = { credentialId: number[]; prfSalt: number[]; iv: number[]; ciphertext: number[] };
export type PortableApplication = {
  v: 1;
  id: string;
  clientId: string;
  clientName: string;
  // Present only for a DPoP-bound capability -- a conventional (non-DPoP)
  // client's approval has no device key at all.
  deviceJkt?: string;
  serviceIds: string[];
  keyIds: string[];
  services?: { id: string; keyIds: string[] }[];
  createdAt: string;
};
export type EncryptedApplicationMetadata = { v: 1; iv: number[]; ciphertext: number[] };

/** Master-derived identity. `none` deliberately stores no private key. */
export type MasterStoredIdentity = {
  v: 4;
  username: string;
  did: string;
  rootKey: string;
  generation: string;
  protection: "none" | "passkey";
  sealed?: SealedPayload;
  applicationMetadata?: EncryptedApplicationMetadata;
};

/** MetaMask-style local vault: the Master seed is encrypted with a password
 * but neither the password nor a plaintext seed is persisted. */
export type PasswordStoredIdentity = {
  v: 5;
  username: string;
  did: string;
  rootKey: string;
  generation: string;
  protection: "password";
  vault: string;
  applicationMetadata?: EncryptedApplicationMetadata;
};

export type StoredIdentity = MasterStoredIdentity | PasswordStoredIdentity;
export type DidLogSnapshot = {
  username: string;
  did: string;
  generation: string;
  didJsonl: string;
  savedAt: string;
};

const DB_NAME = "did-md-identities";
const STORE_NAME = "records";
const GRANT_DB_NAME = "did-md-wallet-authorizations";
const GRANT_STORE_NAME = "grants";
const METADATA_DB_NAME = "did-md-wallet-metadata";
const METADATA_STORE_NAME = "device-bindings";
const LOG_DB_NAME = "did-md-identity-container";
const LOG_STORE_NAME = "did-logs";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Public-only audit metadata for a self-signed OAuth device capability.
 * This contains neither access tokens nor Wallet controller material.
 * deviceJkt is present only for a DPoP-bound grant (a client with its own
 * device key) -- a conventional relying party's capability has none, and
 * that alone (not a separate "protocol" field: there is only one
 * authorization protocol now) is what distinguishes the two in the UI. */
export type WalletOAuthGrant = {
  id: string;
  did: string;
  clientId: string;
  clientName: string;
  deviceJkt?: string;
  scope: string[];
  issuedAt: string;
  expiresAt: string;
  /** Present only when this is restored audit metadata, never a credential. */
  importedAt?: string;
};

/** A user-visible, browser-local description of an authorized device.
 * This makes a DPoP thumbprint and a DIDComm key understandable to the
 * account owner. It is never copied into the public DID Document. */
export type WalletDeviceBinding = {
  v: 1;
  id: string;
  did: string;
  deviceJkt: string;
  label: string;
  createdAt: string;
  clientName?: string;
  didCommKeyId?: string;
};

function random(length: number) {
  return crypto.getRandomValues(new Uint8Array(length));
}

function asBytes(value: unknown, label: string): Uint8Array {
  if (!Array.isArray(value) || !value.every(item => Number.isInteger(item) && item >= 0 && item <= 255)) {
    throw new Error(`Invalid ${label}.`);
  }
  return new Uint8Array(value);
}

async function database(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) request.result.createObjectStore(STORE_NAME, { keyPath: "username" });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Could not open local identity storage."));
  });
}

async function transaction<T>(mode: IDBTransactionMode, operation: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await database();
  try {
    return await new Promise<T>((resolve, reject) => {
      const request = operation(db.transaction(STORE_NAME, mode).objectStore(STORE_NAME));
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error("Local identity storage failed."));
    });
  } finally {
    db.close();
  }
}

export async function readStoredIdentity(username: string): Promise<StoredIdentity | undefined> {
  return transaction<StoredIdentity | undefined>("readonly", store => store.get(username));
}

/** Lists local records without unlocking or exposing any sealed secret. */
export async function listStoredIdentities(): Promise<StoredIdentity[]> {
  const records = await transaction<StoredIdentity[]>("readonly", store => store.getAll());
  return records.filter(record => record && (record.v === 4 || record.v === 5)).sort((a, b) => a.username.localeCompare(b.username));
}

/**
 * did.md intentionally keeps one local identity at a time.  The record, its
 * public history snapshot, and the device/grant descriptions are one unit:
 * leaving any of the latter behind would make a newly loaded identity show
 * data belonging to a previous one.
 *
 * This does not and cannot delete a credential from a platform authenticator;
 * it removes only did.md's browser-local references and encrypted material.
 */
export async function clearLocalIdentityState(): Promise<void> {
  await Promise.all([
    transaction<undefined>("readwrite", store => store.clear()),
    grantTransaction<undefined>("readwrite", store => store.clear()),
    metadataTransaction<undefined>("readwrite", store => store.clear()),
    logTransaction<undefined>("readwrite", store => store.clear()),
  ]);
}

async function writeStoredIdentity(record: StoredIdentity): Promise<void> {
  await transaction<IDBValidKey>("readwrite", store => store.put(record));
}

function sealedPayloadIsValid(value: any): value is SealedPayload {
  return value && typeof value === "object" && Array.isArray(value.credentialId) && Array.isArray(value.prfSalt)
    && Array.isArray(value.iv) && Array.isArray(value.ciphertext)
    && value.credentialId.length >= 16 && value.credentialId.length <= 1024
    && value.prfSalt.length === 32 && value.iv.length === 12 && value.ciphertext.length >= 32 && value.ciphertext.length <= 4096
    && [value.credentialId, value.prfSalt, value.iv, value.ciphertext].every(bytes => bytes.every((item: unknown) => Number.isInteger(item) && item >= 0 && item <= 255));
}

function encryptedApplicationMetadataIsValid(value: any): value is EncryptedApplicationMetadata {
  return value && value.v === 1 && Array.isArray(value.iv) && value.iv.length === 12
    && Array.isArray(value.ciphertext) && value.ciphertext.length >= 16 && value.ciphertext.length <= 262_144
    && [value.iv, value.ciphertext].every(bytes => bytes.every((item: unknown) => Number.isInteger(item) && item >= 0 && item <= 255));
}

function checkedApplicationMetadata(value: any): PortableApplication[] {
  if (!Array.isArray(value) || value.length > 1024) throw new Error("Application keyring metadata is invalid.");
  return value.map(item => {
    if (!item || item.v !== 1 || typeof item.id !== "string" || typeof item.clientId !== "string"
      || typeof item.clientName !== "string" || (item.deviceJkt !== undefined && typeof item.deviceJkt !== "string") || typeof item.createdAt !== "string"
      || !Array.isArray(item.serviceIds) || !item.serviceIds.every((id: unknown) => typeof id === "string")
      || !Array.isArray(item.keyIds) || !item.keyIds.every((id: unknown) => typeof id === "string")
      || (item.services !== undefined && (!Array.isArray(item.services) || item.services.some((service: any) => !service || typeof service.id !== "string" || !Array.isArray(service.keyIds) || !service.keyIds.every((id: unknown) => typeof id === "string"))))) {
      throw new Error("Application keyring metadata is invalid.");
    }
    return { v: 1, id: item.id, clientId: item.clientId, clientName: item.clientName,
      ...(item.deviceJkt !== undefined ? { deviceJkt: item.deviceJkt } : {}),
      serviceIds: [...new Set(item.serviceIds)], keyIds: [...new Set(item.keyIds)],
      ...(item.services ? { services: item.services.map((service: any) => ({ id: service.id, keyIds: [...new Set<string>(service.keyIds)] })) } : {}),
      createdAt: item.createdAt };
  });
}

function copyApplicationEnvelope(value: any): EncryptedApplicationMetadata | undefined {
  if (value === undefined) return undefined;
  if (!encryptedApplicationMetadataIsValid(value)) throw new Error("Encrypted application keyring metadata is invalid.");
  return { v: 1, iv: [...value.iv], ciphertext: [...value.ciphertext] };
}

/** Shared by both a stored keyring record and a DID log snapshot; a snapshot
 * has no rootKey of its own; it just tags which identity's log this is. */
function didIdentifierFieldsAreValid(value: any): boolean {
  return value && typeof value.username === "string" && /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(value.username)
    && typeof value.did === "string" && value.did.startsWith("did:webvh:") && value.did.length <= 4096
    && typeof value.generation === "string" && value.generation.length <= 512;
}

function identityFieldsAreValid(value: any): boolean {
  return didIdentifierFieldsAreValid(value) && typeof value.rootKey === "string" && value.rootKey.length <= 4096;
}

/** Returns a safe copy of a persisted keyring record, or rejects malformed
 * container input before IndexedDB ever receives it. */
function checkedStoredIdentity(value: any): StoredIdentity {
  if (!identityFieldsAreValid(value)) throw new Error("Identity keyring data is invalid.");
  if (value.v === 5 && value.protection === "password") {
    if (typeof value.vault !== "string" || value.vault.length < 80 || value.vault.length > 32_768) throw new Error("Password-protected keyring data is invalid.");
    let parsed: any;
    try { parsed = JSON.parse(value.vault); } catch { throw new Error("Password-protected keyring data is invalid."); }
    if (!parsed || typeof parsed.data !== "string" || typeof parsed.iv !== "string" || typeof parsed.salt !== "string") throw new Error("Password-protected keyring data is invalid.");
    return { v: 5, username: value.username, did: value.did, rootKey: value.rootKey, generation: value.generation, protection: "password", vault: value.vault, ...(value.applicationMetadata ? { applicationMetadata: copyApplicationEnvelope(value.applicationMetadata) } : {}) };
  }
  if (value.v === 4 && (value.protection === "none" || value.protection === "passkey")) {
    if (value.protection === "passkey") {
      if (!sealedPayloadIsValid(value.sealed)) throw new Error("Passkey-protected keyring data is invalid.");
      return { v: 4, username: value.username, did: value.did, rootKey: value.rootKey, generation: value.generation, protection: "passkey", sealed: {
        credentialId: [...value.sealed.credentialId], prfSalt: [...value.sealed.prfSalt], iv: [...value.sealed.iv], ciphertext: [...value.sealed.ciphertext],
      }, ...(value.applicationMetadata ? { applicationMetadata: copyApplicationEnvelope(value.applicationMetadata) } : {}) };
    }
    return { v: 4, username: value.username, did: value.did, rootKey: value.rootKey, generation: value.generation, protection: "none", ...(value.applicationMetadata ? { applicationMetadata: copyApplicationEnvelope(value.applicationMetadata) } : {}) };
  }
  throw new Error("This identity keyring version is unsupported.");
}

/** Restores an entire local keyring record from an encrypted identity
 * container. Existing records are intentionally never overwritten. */
export async function restoreIdentityKeyringRecord(value: unknown): Promise<boolean> {
  const record = checkedStoredIdentity(value);
  if (await readStoredIdentity(record.username)) return false;
  await writeStoredIdentity(record);
  return true;
}

/** A JSON-only defensive copy for encryption/export. */
export function exportIdentityKeyringRecord(value: StoredIdentity): StoredIdentity {
  return checkedStoredIdentity(value);
}

async function applicationMetadataKey(masterSeed: Uint8Array): Promise<CryptoKey> {
  if (!(masterSeed instanceof Uint8Array) || masterSeed.length !== 32) throw new Error("A Passphrase is required for application metadata.");
  const label = encoder.encode("did.md/application-keyring/v1\0");
  const material = new Uint8Array(label.length + masterSeed.length);
  material.set(label); material.set(masterSeed, label.length);
  const digest = await crypto.subtle.digest("SHA-256", material);
  material.fill(0);
  return crypto.subtle.importKey("raw", digest, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function readPortableApplications(record: StoredIdentity, masterSeed: Uint8Array): Promise<PortableApplication[]> {
  if (!record.applicationMetadata) return [];
  const key = await applicationMetadataKey(masterSeed);
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: asBytes(record.applicationMetadata.iv, "application metadata IV") }, key, asBytes(record.applicationMetadata.ciphertext, "application metadata ciphertext"));
  } catch { throw new Error("Could not decrypt application keyring metadata."); }
  try { return checkedApplicationMetadata(JSON.parse(decoder.decode(plaintext))); }
  catch { throw new Error("Application keyring metadata is invalid."); }
}

export async function savePortableApplications(record: StoredIdentity, masterSeed: Uint8Array, applications: PortableApplication[]): Promise<StoredIdentity> {
  const checked = checkedApplicationMetadata(applications);
  const key = await applicationMetadataKey(masterSeed);
  const iv = random(12);
  const plaintext = encoder.encode(JSON.stringify(checked));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext));
  plaintext.fill(0);
  const next = checkedStoredIdentity({ ...record, applicationMetadata: { v: 1, iv: [...iv], ciphertext: [...ciphertext] } });
  await writeStoredIdentity(next);
  return next;
}

/** Restores only an existing passkey-encrypted Master envelope. The Master
 * bytes remain ciphertext; it can be opened only by the same WebAuthn PRF
 * credential (or recovered separately with the 24-word mnemonic). */
export async function restorePasskeyStoredMasterIdentity(args: {
  username: string; did: string; rootKey: string; generation: string; sealed: SealedPayload;
}): Promise<void> {
  if (!sealedPayloadIsValid(args.sealed)) throw new Error("Passkey-encrypted Master backup data is invalid.");
  await writeStoredIdentity({
    v: 4, username: args.username, did: args.did, rootKey: args.rootKey, generation: args.generation,
    protection: "passkey", sealed: {
      credentialId: [...args.sealed.credentialId], prfSalt: [...args.sealed.prfSalt],
      iv: [...args.sealed.iv], ciphertext: [...args.sealed.ciphertext],
    },
  });
}

async function grantDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(GRANT_DB_NAME, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(GRANT_STORE_NAME)) request.result.createObjectStore(GRANT_STORE_NAME, { keyPath: "id" });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Could not open local authorization storage."));
  });
}

async function grantTransaction<T>(mode: IDBTransactionMode, operation: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await grantDatabase();
  try {
    return await new Promise<T>((resolve, reject) => {
      const request = operation(db.transaction(GRANT_STORE_NAME, mode).objectStore(GRANT_STORE_NAME));
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error("Local authorization storage failed."));
    });
  } finally {
    db.close();
  }
}

function oauthGrantIsValid(value: any): value is WalletOAuthGrant {
  return value && typeof value.id === "string" && typeof value.did === "string"
    && typeof value.clientId === "string" && typeof value.clientName === "string"
    && (value.deviceJkt === undefined || typeof value.deviceJkt === "string")
    && Array.isArray(value.scope) && value.scope.every(scope => typeof scope === "string")
    && typeof value.issuedAt === "string" && typeof value.expiresAt === "string"
    && (value.importedAt === undefined || typeof value.importedAt === "string");
}

export async function saveWalletOAuthGrant(grant: WalletOAuthGrant): Promise<void> {
  if (!oauthGrantIsValid(grant)) throw new Error("OAuth capability metadata is invalid.");
  const db = await grantDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = db.transaction(GRANT_STORE_NAME, "readwrite");
      const store = transaction.objectStore(GRANT_STORE_NAME);
      // Re-authorizing the same app from the same device supersedes its
      // previous grant rather than accumulating a new history entry under a
      // fresh (capability.id-keyed) row forever -- the Wallet UI shows one
      // card per app (renderWalletGrants), grouping by clientId; without
      // this, every reconnect/edit-server/logout round left its own
      // permanent row behind (found live, 2026-09-14: three "Biset" cards
      // after one login/logout/login cycle).
      const cursorRequest = store.openCursor();
      cursorRequest.onsuccess = () => {
        const cursor = cursorRequest.result;
        if (!cursor) return;
        const existing = cursor.value as WalletOAuthGrant;
        if (existing.did === grant.did && existing.clientId === grant.clientId && existing.deviceJkt === grant.deviceJkt) cursor.delete();
        cursor.continue();
      };
      store.put({ ...grant });
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error ?? new Error("Local authorization storage failed."));
    });
  } finally {
    db.close();
  }
}

export async function listWalletOAuthGrants(): Promise<WalletOAuthGrant[]> {
  const values = await grantTransaction<WalletOAuthGrant[]>("readonly", store => store.getAll());
  return values.filter(oauthGrantIsValid).sort((a, b) => b.issuedAt.localeCompare(a.issuedAt));
}

function deviceBindingIsValid(value: any): value is WalletDeviceBinding {
  return value && value.v === 1 && typeof value.id === "string" && typeof value.did === "string"
    && typeof value.deviceJkt === "string" && typeof value.label === "string" && value.label.length <= 160
    && typeof value.createdAt === "string"
    && (value.clientName === undefined || typeof value.clientName === "string")
    && (value.didCommKeyId === undefined || typeof value.didCommKeyId === "string");
}

async function metadataDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(METADATA_DB_NAME, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(METADATA_STORE_NAME)) request.result.createObjectStore(METADATA_STORE_NAME, { keyPath: "id" });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Could not open local metadata storage."));
  });
}

async function metadataTransaction<T>(mode: IDBTransactionMode, operation: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await metadataDatabase();
  try {
    return await new Promise<T>((resolve, reject) => {
      const request = operation(db.transaction(METADATA_STORE_NAME, mode).objectStore(METADATA_STORE_NAME));
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error("Local metadata storage failed."));
    });
  } finally {
    db.close();
  }
}

export async function saveWalletDeviceBinding(binding: WalletDeviceBinding): Promise<void> {
  if (!deviceBindingIsValid(binding)) throw new Error("Device metadata is invalid.");
  await metadataTransaction<IDBValidKey>("readwrite", store => store.put({ ...binding }));
}

export async function listWalletDeviceBindings(): Promise<WalletDeviceBinding[]> {
  const values = await metadataTransaction<WalletDeviceBinding[]>("readonly", store => store.getAll());
  return values.filter(deviceBindingIsValid).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

async function logDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(LOG_DB_NAME, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(LOG_STORE_NAME)) request.result.createObjectStore(LOG_STORE_NAME, { keyPath: "username" });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Could not open local DID log storage."));
  });
}

async function logTransaction<T>(mode: IDBTransactionMode, operation: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await logDatabase();
  try {
    return await new Promise<T>((resolve, reject) => {
      const request = operation(db.transaction(LOG_STORE_NAME, mode).objectStore(LOG_STORE_NAME));
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error("Local DID log storage failed."));
    });
  } finally {
    db.close();
  }
}

/** Stores a complete public DID history alongside an imported container. It
 * is a portability aid only; the network-hosted log remains authoritative. */
export async function saveDidLogSnapshot(snapshot: DidLogSnapshot): Promise<void> {
  if (!didIdentifierFieldsAreValid(snapshot) || typeof snapshot.didJsonl !== "string" || !snapshot.didJsonl.endsWith("\n")
    || snapshot.didJsonl.length > 16 * 1024 * 1024 || typeof snapshot.savedAt !== "string") {
    throw new Error("DID log snapshot is invalid.");
  }
  await logTransaction<IDBValidKey>("readwrite", store => store.put({ ...snapshot }));
}

export async function readDidLogSnapshot(username: string): Promise<DidLogSnapshot | undefined> {
  const value = await logTransaction<DidLogSnapshot | undefined>("readonly", store => store.get(username));
  if (!value || !didIdentifierFieldsAreValid(value) || typeof value.didJsonl !== "string" || !value.didJsonl.endsWith("\n")
    || value.didJsonl.length > 16 * 1024 * 1024 || typeof value.savedAt !== "string") return undefined;
  return { ...value };
}


function prfResult(credential: Credential): Uint8Array {
  const result = (credential as PublicKeyCredential).getClientExtensionResults().prf as any;
  const first = result?.results?.first;
  if (!first) throw new Error("This passkey does not support the PRF extension required for encryption.");
  return new Uint8Array(first);
}

// Fixed at the registrable domain (not location.hostname) so a passkey keeps
// working across did.md's own subdomains (e.g. registered while served from
// did.md, still usable from app.did.md).
const PASSKEY_RP_ID = "did.md";

async function passkeyPrf(credentialId: number[], prfSalt: number[]): Promise<CryptoKey> {
  const credential = await navigator.credentials.get({
    publicKey: {
      challenge: random(32),
      rpId: PASSKEY_RP_ID,
      allowCredentials: [{ type: "public-key", id: new Uint8Array(credentialId) }],
      userVerification: "required",
      extensions: { prf: { eval: { first: new Uint8Array(prfSalt) } } } as any,
    },
  });
  if (!credential) throw new Error("Passkey authentication was cancelled.");
  return crypto.subtle.importKey("raw", prfResult(credential), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

/** Registers a passkey only when the user explicitly asks for local sealing. */
export async function createPasskeyProtector(username: string): Promise<PasskeyProtector> {
  if (!window.PublicKeyCredential || !navigator.credentials) throw new Error("Passkeys are not available in this browser.");
  const prfSalt = random(32);
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: random(32),
      rp: { id: PASSKEY_RP_ID, name: "did.md" },
      user: { id: random(32), name: `did.md:${username}`, displayName: username },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      timeout: 60_000,
      extensions: { prf: { eval: { first: prfSalt } } } as any,
    },
  });
  if (!credential) throw new Error("Passkey registration was cancelled.");
  const result = (credential as PublicKeyCredential).getClientExtensionResults().prf as any;
  if (result?.enabled !== true) throw new Error("The selected passkey does not support PRF encryption.");
  const credentialId = [...new Uint8Array((credential as PublicKeyCredential).rawId)];
  return { mode: "passkey", credentialId, prfSalt: [...prfSalt], key: await passkeyPrf(credentialId, [...prfSalt]) };
}

async function sealPayload(payload: object, protector: PasskeyProtector): Promise<SealedPayload> {
  const iv = random(12);
  const plaintext = encoder.encode(JSON.stringify(payload));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, protector.key, plaintext);
  return { credentialId: protector.credentialId, prfSalt: protector.prfSalt, iv: [...iv], ciphertext: [...new Uint8Array(ciphertext)] };
}

async function unsealPayload(record: { sealed?: SealedPayload }): Promise<{ decoded: any; protector: PasskeyProtector }> {
  if (!record.sealed) throw new Error("Passkey-protected local identity has no sealed data.");
  const { credentialId, prfSalt, iv, ciphertext } = record.sealed;
  const key = await passkeyPrf(credentialId, prfSalt);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: asBytes(iv, "passkey IV") }, key, asBytes(ciphertext, "passkey ciphertext"));
  let decoded: any;
  try { decoded = JSON.parse(decoder.decode(plaintext)); } catch { throw new Error("Could not decrypt the local identity record."); }
  return { decoded, protector: { mode: "passkey", key, credentialId, prfSalt } };
}

/** Unlocks the one Master secret held in a v4 passkey-sealed record. */
export async function unlockMasterStoredIdentity(record: StoredIdentity): Promise<{ masterSeed: Uint8Array; protector: PasskeyProtector }> {
  if (record.v !== 4) throw new Error("This identity is not passkey-protected.");
  if (record.protection !== "passkey") throw new Error("No Passphrase is stored in this browser. Enter the 24-word Master phrase.");
  const { decoded, protector } = await unsealPayload(record);
  return { masterSeed: asBytes(decoded.masterSeed, "Passphrase"), protector };
}

/** Unlocks a MetaMask-style password vault. The password is supplied only for
 * this invocation and is never written to IndexedDB. */
export async function unlockPasswordStoredIdentity(record: StoredIdentity, password: string): Promise<Uint8Array> {
  if (record.v !== 5 || record.protection !== "password") throw new Error("This identity is not protected by a password.");
  if (typeof password !== "string" || password.length < 8) throw new Error("Password must be at least 8 characters.");
  let decoded: any;
  try {
    decoded = await decryptVault(password, record.vault);
  } catch {
    throw new Error("Incorrect password.");
  }
  return asBytes(decoded?.masterSeed, "encrypted Passphrase");
}

/**
 * Saves only public metadata unless a passkey protector is supplied. There is
 * intentionally no plaintext-Master branch.
 */
export async function saveMasterStoredIdentity(args: {
  username: string; did: string; rootKey: string; generation: string; masterSeed?: Uint8Array; protector?: PasskeyProtector; applicationMetadata?: EncryptedApplicationMetadata;
}): Promise<MasterStoredIdentity> {
  const base = { v: 4 as const, username: args.username, did: args.did, rootKey: args.rootKey, generation: args.generation, ...(args.applicationMetadata ? { applicationMetadata: copyApplicationEnvelope(args.applicationMetadata) } : {}) };
  let record: MasterStoredIdentity;
  if (args.protector) {
    if (!args.masterSeed) throw new Error("A Passphrase is required before it can be encrypted with a passkey.");
    record = { ...base, protection: "passkey", sealed: await sealPayload({ masterSeed: [...args.masterSeed] }, args.protector) };
  } else {
    record = { ...base, protection: "none" };
  }
  await writeStoredIdentity(record);
  return record;
}

/** Creates a password-protected local vault using MetaMask's maintained
 * browser-passworder (PBKDF2 + AES-GCM). */
export async function savePasswordStoredIdentity(args: {
  username: string; did: string; rootKey: string; generation: string; masterSeed: Uint8Array; password: string; applicationMetadata?: EncryptedApplicationMetadata;
}): Promise<PasswordStoredIdentity> {
  if (typeof args.password !== "string" || args.password.length < 8) throw new Error("Password must be at least 8 characters.");
  const vault = await encryptVault(args.password, { masterSeed: [...args.masterSeed] });
  const record: PasswordStoredIdentity = {
    v: 5, username: args.username, did: args.did, rootKey: args.rootKey, generation: args.generation,
    protection: "password", vault, ...(args.applicationMetadata ? { applicationMetadata: copyApplicationEnvelope(args.applicationMetadata) } : {}),
  };
  await writeStoredIdentity(record);
  return record;
}

export async function restorePasswordStoredMasterIdentity(args: {
  username: string; did: string; rootKey: string; generation: string; vault: string;
}): Promise<void> {
  if (typeof args.vault !== "string" || args.vault.length < 80 || args.vault.length > 32_768) throw new Error("Password vault backup data is invalid.");
  let parsed: any;
  try { parsed = JSON.parse(args.vault); } catch { throw new Error("Password vault backup data is invalid."); }
  if (!parsed || typeof parsed.data !== "string" || typeof parsed.iv !== "string" || typeof parsed.salt !== "string") throw new Error("Password vault backup data is invalid.");
  await writeStoredIdentity({
    v: 5, username: args.username, did: args.did, rootKey: args.rootKey, generation: args.generation,
    protection: "password", vault: args.vault,
  });
}

/** Updates public metadata after a DID rotation without needing the password
 * again: the encrypted Master vault itself is unchanged. */
export async function updatePasswordStoredIdentityMetadata(record: PasswordStoredIdentity, args: {
  did: string; rootKey: string; generation: string;
}): Promise<PasswordStoredIdentity> {
  const next: PasswordStoredIdentity = { ...record, did: args.did, rootKey: args.rootKey, generation: args.generation };
  await writeStoredIdentity(next);
  return next;
}
