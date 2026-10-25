import { entropyToMnemonic, mnemonicToEntropy, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { createDataIntegrityProof, keyFromPrivateKey, type Ed25519Key } from "../../vh/src/index.ts";

// Data Integrity proofs are packages/vh's; re-exported because wallet code and tests reach for them here.
export { createDataIntegrityProof };

const encoder = new TextEncoder();

export type ControllerKey = Ed25519Key;
export type IdentityMaterial = {
  masterSeed: Uint8Array;
  root: ControllerKey;
  sign: ControllerKey;
  nextSpare: ControllerKey;
  /** The single offline recovery secret for this identity. */
  masterMnemonic: string;
  /** The SLIP-0010 generation of `nextSpare`. */
  nextSpareIndex: number;
};

/** Audience-bound authorization for an RP-supplied public key. */
export async function createKeyAuthorizationCredentialWire(args: {
  issuer: string;
  audience: string;
  subject: string;
  generation: string;
  publicKey: { type: string; publicKeyMultibase: string };
  purposes: string[];
  issuedAt: string;
  expiresAt: string;
  rootPrivateKey: Uint8Array;
  signPrivateKey: Uint8Array;
}): Promise<string> {
  if (!args.issuer.startsWith("did:vh:") || !args.audience || !/^urn:uuid:[0-9a-f-]{36}$/i.test(args.subject)
    || !/^[1-9][0-9]*-[A-Za-z0-9_-]{20,200}$/.test(args.generation)
    || !args.publicKey.type.trim() || !args.publicKey.publicKeyMultibase.startsWith("z")
    || !args.purposes.length || args.purposes.some(value => !value.trim())
    || !Number.isFinite(Date.parse(args.issuedAt)) || Date.parse(args.expiresAt) <= Date.parse(args.issuedAt)
    || args.rootPrivateKey.length !== 32 || args.signPrivateKey.length !== 32) throw new Error("The key authorization request is invalid.");
  const unsigned = {
    type: "did.md/KeyAuthorizationCredential", version: 1,
    issuer: args.issuer, audience: args.audience, subject: args.subject,
    generation: args.generation,
    publicKey: args.publicKey, purposes: args.purposes,
    issuedAt: args.issuedAt, expiresAt: args.expiresAt,
  };
  const signingBytes = new TextEncoder().encode(jcs({ label: "did.md/key-authorization/v1", ...unsigned }));
  const credential = {
    ...unsigned,
    rootSignature: base64url(ed25519.sign(signingBytes, args.rootPrivateKey)),
    signSignature: base64url(ed25519.sign(signingBytes, args.signPrivateKey)),
  };
  return base64url(new TextEncoder().encode(jcs(credential)));
}

/** A stable, per-identity value derived from the Root private key -- never
 * published anywhere, reproducible by any device that holds this identity's
 * Root key (i.e. any device signed in through the same Wallet mnemonic), and
 * computationally infeasible to derive from the DID alone (only the Root
 * *public* key is ever published). Lets a relying party's own devices agree
 * on a value -- e.g. a storage locator -- without that value ever entering
 * the (public) DID Document, the way `createKeyAuthorizationCredentialWire`
 * above lets an RP get a signed credential without the Wallet ever handing
 * out a signing key. `purpose`/`context` are domain-separation labels the RP
 * supplies (and the wallet signs over, via HKDF's `info`) so distinct
 * requests never collide; the Root key itself is only ever the HKDF input
 * keying material, never transmitted. */
export function deriveWalletSecret(rootPrivateKey: Uint8Array, purpose: string, context: string | undefined, length = 32): Uint8Array {
  if (rootPrivateKey.length !== 32) throw new Error("The Root private key is invalid.");
  if (!/^[A-Za-z][A-Za-z0-9:._-]{0,127}$/.test(purpose)) throw new Error("The derived-secret purpose is invalid.");
  if (context !== undefined && (typeof context !== "string" || !context.trim() || context.length > 2048)) throw new Error("The derived-secret context is invalid.");
  if (!Number.isInteger(length) || length < 16 || length > 64) throw new Error("The derived-secret length is invalid.");
  const info = encoder.encode(`did.md/derived-secret/v1:${purpose}${context !== undefined ? `:${context}` : ""}`);
  return hkdf(sha256, rootPrivateKey, undefined, info, length);
}

// RFC 8785 canonical JSON, for the wallet's own credentials (packages/vh's canonicalize is the log's).
export function jcs(value: any): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("JSON contains a non-finite number");
    return Object.is(value, -0) ? "0" : JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${jcs(value[key])}`).join(",")}}`;
}

function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function controllerFromPrivate(privateKey: Uint8Array): ControllerKey {
  return keyFromPrivateKey(privateKey);
}

/** Decode a private OKP/Ed25519 JWK for one in-browser signing operation. */
export function controllerFromEd25519Jwk(value: any): ControllerKey {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || value.kty !== "OKP" || value.crv !== "Ed25519"
    || typeof value.x !== "string" || typeof value.d !== "string") {
    throw new Error("The signing key must be a private Ed25519 JWK (kty: OKP, crv: Ed25519, x, d).");
  }
  const privateKey = base64urlDecode(value.d, "JWK d");
  const declaredPublicKey = base64urlDecode(value.x, "JWK x");
  if (privateKey.length !== 32 || declaredPublicKey.length !== 32) throw new Error("JWK x and d must each be 32 bytes for Ed25519.");
  const derived = ed25519.getPublicKey(privateKey);
  if (!derived.every((byte, index) => byte === declaredPublicKey[index])) throw new Error("JWK x does not match its private key d.");
  const controller = controllerFromPrivate(privateKey);
  privateKey.fill(0);
  return controller;
}

export function base64urlDecode(value: string, label: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error(`${label} must be base64url without padding.`);
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  try { return Uint8Array.from(atob(padded), character => character.charCodeAt(0)); }
  catch { throw new Error(`${label} is not valid base64url.`); }
}

function normaliseMnemonic(value: string): string {
  return value.trim().toLowerCase().replace(/\s+/g, " ");
}

export function mnemonicForSeed(seed: Uint8Array): string {
  if (seed.length !== 32) throw new Error("A 24-word mnemonic requires a 32-byte seed.");
  return entropyToMnemonic(seed, wordlist);
}

export function seedFromMnemonic(value: string, label = "Mnemonic"): Uint8Array {
  const mnemonic = normaliseMnemonic(value);
  if (!validateMnemonic(mnemonic, wordlist)) throw new Error(`${label} must be a valid 24-word mnemonic.`);
  const seed = mnemonicToEntropy(mnemonic, wordlist);
  if (seed.length !== 32) throw new Error(`${label} must contain 256-bit entropy.`);
  return seed;
}

async function hmacSha512(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const hmac = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-512" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", hmac, data));
}

/**
 * SLIP-0010 Ed25519 supports private, hardened derivation only.  The profile
 * is deliberately small and versionable:
 *
 *   m/0'       genesis Root (and initial Sign) key
 *   m/1'/n'    pre-rotation key for generation n
 *
 * The BIP39 phrase encodes 32 bytes of random entropy. It is
 * not sent to the server and it is never a DID Document value.
 */
async function deriveHardenedEd25519(masterSeed: Uint8Array, path: number[]): Promise<ControllerKey> {
  if (masterSeed.length !== 32) throw new Error("Master seed must be 32 bytes.");
  let node = await hmacSha512(encoder.encode("ed25519 seed"), masterSeed);
  for (const index of path) {
    if (!Number.isInteger(index) || index < 0 || index >= 0x80000000) {
      throw new Error("Invalid hardened derivation index.");
    }
    const childInput = new Uint8Array(37);
    childInput[0] = 0;
    childInput.set(node.slice(0, 32), 1);
    new DataView(childInput.buffer).setUint32(33, index + 0x80000000, false);
    node = await hmacSha512(node.slice(32), childInput);
  }
  return controllerFromPrivate(node.slice(0, 32));
}

/** SLIP-0010 Ed25519 root derivation at m/0'. */
export async function rootFromMasterSeed(masterSeed: Uint8Array): Promise<ControllerKey> {
  return deriveHardenedEd25519(masterSeed, [0]);
}

/** The `n`th future authorization key at m/1'/n'. */
export async function spareFromMasterSeed(masterSeed: Uint8Array, index: number): Promise<ControllerKey> {
  return deriveHardenedEd25519(masterSeed, [1, index]);
}

export async function createIdentityMaterial(): Promise<IdentityMaterial> {
  const masterSeed = crypto.getRandomValues(new Uint8Array(32));
  const root = await rootFromMasterSeed(masterSeed);
  const nextSpare = await spareFromMasterSeed(masterSeed, 0);
  return {
    masterSeed,
    root,
    sign: root,
    nextSpare,
    masterMnemonic: mnemonicForSeed(masterSeed),
    nextSpareIndex: 0,
  };
}

export function spareFromMnemonic(value: string): ControllerKey {
  return controllerFromPrivate(seedFromMnemonic(value, "Spare Key mnemonic"));
}

export async function signEntry(unsigned: object, privateKey: Uint8Array, verificationKey: string, created: string): Promise<any> {
  const proof = await createDataIntegrityProof(unsigned, {
    privateKey,
    verificationMethod: `did:key:${verificationKey}#${verificationKey}`,
    proofPurpose: "assertionMethod",
    created,
  });
  return { ...unsigned, proof: [proof] };
}

/**
 * A compact EdDSA-signed JWT, self-issued directly by the identity's own
 * Root key (`#pass-1`) -- no dito server key is ever involved in signing
 * this token, so a relying party that resolves `<did>#pass-1` itself (from
 * the DID's published did.jsonl) can verify it without trusting dito as a
 * third-party signer. `claims` should already include the caller's own
 * iss/sub/aud/iat/exp and any profile fields; this only wraps and signs it.
 */
export function createSelfIssuedIdToken(claims: Record<string, unknown>, args: {
  privateKey: Uint8Array; did: string;
  /** Where the signer's log is published (`https://alice.did.md`), carried in the `kid` as the DID URL's `src`: a did:vh DID names none. */
  src?: string;
}): string {
  if (args.privateKey.length !== 32) throw new Error("An Ed25519 private key must be 32 bytes.");
  const header = { alg: "EdDSA", typ: "JWT", kid: `${args.did}${args.src ? `?src=${encodeURIComponent(args.src.replace(/\/+$/, ""))}` : ""}#pass-1` };
  const headerPart = base64url(encoder.encode(JSON.stringify(header)));
  const payloadPart = base64url(encoder.encode(JSON.stringify(claims)));
  const signature = ed25519.sign(encoder.encode(`${headerPart}.${payloadPart}`), args.privateKey);
  return `${headerPart}.${payloadPart}.${base64url(signature)}`;
}
