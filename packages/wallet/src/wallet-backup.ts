// A portable did.md identity container is one JWE Compact Serialization.
// Its plaintext is a versioned manifest and its logical files (DID logs,
// encrypted/local keyring records, and non-secret device metadata).  This is
// deliberately close to DIF's Wallet Backup Container direction while that
// work is still a strawman.  JWE itself is standard RFC 7516 / RFC 7518.
//
// A passkey private key, DPoP private key, OAuth token, or live capability
// must never be serialised: those are device-bound, not portable identity
// material.

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const GCM_IV_BYTES = 12;
const GCM_TAG_BYTES = 16;
const MAX_CONTAINER_CHARS = 32 * 1024 * 1024;
const IDENTITY_CONTAINER_TYP = "application/did.md.identity-container+jwe";
const IDENTITY_CONTAINER_CTY = "application/did.md.identity-container+json";

function random(length: number) {
  return crypto.getRandomValues(new Uint8Array(length));
}

function base64url(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlBytes(value: string, label: string) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error(`${label} must be base64url.`);
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  try {
    return Uint8Array.from(atob(padded), char => char.charCodeAt(0));
  } catch {
    throw new Error(`${label} must be base64url.`);
  }
}

function compactPart(value: string, label: string) {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw new Error(`The backup ${label} is invalid.`);
  return value ? base64urlBytes(value, `backup ${label}`) : new Uint8Array();
}

const MNEMONIC_ALG = "did.md-mnemonic-hkdf+A256KW";
const HKDF_SALT_BYTES = 16;
const HKDF_INFO = encoder.encode("did.md/identity-container-kek");

function checkedMasterSeed(value: Uint8Array) {
  if (!(value instanceof Uint8Array) || value.length !== 32) throw new Error("A 32-byte Master seed is required.");
  return value;
}

// PBES2 exists to stretch a low-entropy human password; a 24-word Master
// mnemonic is already ~256 bits of entropy, so deriving its wrapping key
// through plain HKDF is both simpler and appropriate for the input.
async function mnemonicWrappingKey(masterSeed: Uint8Array, salt: Uint8Array) {
  const baseKey = await crypto.subtle.importKey("raw", checkedMasterSeed(masterSeed), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: HKDF_INFO },
    baseKey,
    { name: "AES-KW", length: 256 },
    false,
    ["wrapKey", "unwrapKey"],
  );
}

async function encryptWithMnemonic(payload: object, masterSeed: Uint8Array, typ: string, cty: string) {
  checkedMasterSeed(masterSeed);
  const salt = random(HKDF_SALT_BYTES);
  const header = { typ, cty, alg: MNEMONIC_ALG, enc: "A256GCM", hs: base64url(salt) };
  const protectedHeader = base64url(encoder.encode(JSON.stringify(header)));
  const kek = await mnemonicWrappingKey(masterSeed, salt);
  const cek = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const encryptedKey = new Uint8Array(await crypto.subtle.wrapKey("raw", cek, kek, "AES-KW"));
  const iv = random(GCM_IV_BYTES);
  const sealed = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: encoder.encode(protectedHeader), tagLength: 128 },
    cek,
    encoder.encode(JSON.stringify(payload)),
  ));
  const ciphertext = sealed.slice(0, -GCM_TAG_BYTES);
  const tag = sealed.slice(-GCM_TAG_BYTES);
  return `${protectedHeader}.${base64url(encryptedKey)}.${base64url(iv)}.${base64url(ciphertext)}.${base64url(tag)}`;
}

async function decryptWithMnemonic(compactJwe: string, masterSeed: Uint8Array, typ: string, cty: string, label: string) {
  checkedMasterSeed(masterSeed);
  if (typeof compactJwe !== "string" || compactJwe.length > MAX_CONTAINER_CHARS) throw new Error("The identity container is invalid or too large.");
  const parts = compactJwe.trim().split(".");
  if (parts.length !== 5) throw new Error("The backup is not a JWE Compact Serialization.");
  const [protectedHeader, encryptedKeyPart, ivPart, ciphertextPart, tagPart] = parts;
  const header = parseJson(compactPart(protectedHeader, "protected header"), "backup protected header");
  if (!header || typeof header !== "object" || Array.isArray(header)
    || header.typ !== typ || header.cty !== cty
    || header.alg !== MNEMONIC_ALG || header.enc !== "A256GCM" || typeof header.hs !== "string") {
    throw new Error(`This is not a ${label}.`);
  }
  const kek = await mnemonicWrappingKey(masterSeed, base64urlBytes(header.hs, "backup hs"));
  let cek: CryptoKey;
  try {
    cek = await crypto.subtle.unwrapKey("raw", compactPart(encryptedKeyPart, "encrypted key"), kek, "AES-KW", { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  } catch {
    throw new Error("The Passphrase is incorrect or the backup was altered.");
  }
  const iv = compactPart(ivPart, "IV");
  if (iv.length !== GCM_IV_BYTES) throw new Error("The backup IV is invalid.");
  const tag = compactPart(tagPart, "authentication tag");
  if (tag.length !== GCM_TAG_BYTES) throw new Error("The backup authentication tag is invalid.");
  const ciphertext = compactPart(ciphertextPart, "ciphertext");
  const sealed = new Uint8Array(ciphertext.length + tag.length);
  sealed.set(ciphertext); sealed.set(tag, ciphertext.length);
  try {
    const plaintext = new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: encoder.encode(protectedHeader), tagLength: 128 }, cek, sealed,
    ));
    return parseJson(plaintext, "decrypted metadata");
  } catch {
    throw new Error("The Passphrase is incorrect or the backup was altered.");
  }
}

function parseJson(bytes: Uint8Array, label: string) {
  try { return JSON.parse(decoder.decode(bytes)); }
  catch { throw new Error(`The ${label} is not valid JSON.`); }
}

/** Creates the current, complete portable identity container. Wrapped
 * directly by the identity's own Master seed -- ~256 bits of entropy -- so
 * opening the file needs only the same 24-word mnemonic the identity already
 * requires, not a separate password to remember. */
export async function encryptIdentityContainer(payload: object, masterSeed: Uint8Array) {
  return encryptWithMnemonic(payload, masterSeed, IDENTITY_CONTAINER_TYP, IDENTITY_CONTAINER_CTY);
}

/** Opens the current identity-container media type using its Master seed. */
export async function decryptIdentityContainer(compactJwe: string, masterSeed: Uint8Array) {
  return decryptWithMnemonic(compactJwe, masterSeed, IDENTITY_CONTAINER_TYP, IDENTITY_CONTAINER_CTY, "did.md identity container");
}

