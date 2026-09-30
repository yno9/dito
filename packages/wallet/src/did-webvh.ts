import { entropyToMnemonic, mnemonicToEntropy, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  Ed25519Signer, authenticationPublicKey, createDataIntegrityProof, createLog, keyFromPrivateKey, nextKeyHash, resolveDidWebvh, updateLog,
  type Ed25519Key,
} from "../../webvh/src/index.ts";

// Data Integrity proofs are didwebvh-ts's (packages/webvh/src/proof.ts);
// re-exported because wallet code and tests reach for them here.
export { createDataIntegrityProof };

const SCID = "{SCID}";
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
  if (!args.issuer.startsWith("did:webvh:") || !args.audience || !/^urn:uuid:[0-9a-f-]{36}$/i.test(args.subject)
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

// RFC 8785 canonical JSON, for the wallet's own credentials below (not for
// did:webvh: didwebvh-ts canonicalizes log entries and proofs itself, but does
// not export its canonicalizer -- see JOURNAL.md).
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

function didFor(scid: string, username: string, domain: string): string {
  return `did:webvh:${scid}:${username}.${domain}`;
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
}): string {
  if (args.privateKey.length !== 32) throw new Error("An Ed25519 private key must be 32 bytes.");
  const header = { alg: "EdDSA", typ: "JWT", kid: `${args.did}#pass-1` };
  const headerPart = base64url(encoder.encode(JSON.stringify(header)));
  const payloadPart = base64url(encoder.encode(JSON.stringify(claims)));
  const signature = ed25519.sign(encoder.encode(`${headerPart}.${payloadPart}`), args.privateKey);
  return `${headerPart}.${payloadPart}.${base64url(signature)}`;
}

/**
 * Verifies a compact EdDSA JWS whose `kid` header is `<did:webvh DID>#<fragment>`,
 * resolving the signer's authentication key by fetching that DID's own
 * published log (see resolveDidWebvhDocument). Used to verify a JAR
 * (RFC 9101) Authorization Request object signed by a relying party's own
 * DID key -- the wallet-UI-side counterpart of packages/did-verify's
 * verifyViaDidWebvh, reimplemented against browser-safe primitives (see the
 * comment above parseWebvhDid). Returns the verified JWT payload plus the
 * resolver's `service` array, so the caller can also check the JAR's
 * claimed redirect_uri against what the RP's own DID document publishes
 * (PLAN6 §0.3bis) without a second resolution round-trip.
 */
export async function verifyRequestObjectJws(jwt: string): Promise<{ payload: Record<string, unknown>; rpDid: string; service: any[] }> {
  const parts = jwt.split(".");
  if (parts.length !== 3) throw new Error("The request object is malformed.");
  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    header = JSON.parse(new TextDecoder().decode(base64urlDecode(parts[0], "request object header")));
    payload = JSON.parse(new TextDecoder().decode(base64urlDecode(parts[1], "request object payload")));
  } catch { throw new Error("The request object is malformed."); }
  if (header.alg !== "EdDSA" || typeof header.kid !== "string") throw new Error("The request object header is invalid.");
  const hashIndex = header.kid.indexOf("#");
  if (hashIndex <= 0) throw new Error("The request object kid has no fragment.");
  const rpDid = header.kid.slice(0, hashIndex);
  if (!rpDid.startsWith("did:webvh:")) throw new Error("The request object kid is not a did:webvh DID.");
  const resolved = await resolveDidWebvh(rpDid);
  const document = resolved.doc as Record<string, any>;
  const publicKey = authenticationPublicKey(document, rpDid, header.kid);
  const signature = base64urlDecode(parts[2], "request object signature");
  if (!ed25519.verify(signature, encoder.encode(`${parts[0]}.${parts[1]}`), publicKey)) throw new Error("The request object signature is invalid.");
  return { payload, rpDid, service: Array.isArray(document.service) ? document.service : [] };
}

export async function buildGenesis(args: {
  username: string; displayName?: string; root: ControllerKey; sign: ControllerKey; nextSpare: ControllerKey; domain: string; api?: string;
  /** PLAN6: a relying party's own DID publishes its redirect_uri(s) here (see PLAN6 §0.3bis). Defaults to none, matching every existing caller. */
  service?: { id: string; type: string; serviceEndpoint: string }[];
}): Promise<any> {
  const placeholderDid = didFor(SCID, args.username, args.domain);
  const didDocument = {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
    id: placeholderDid,
    verificationMethod: [{
      // A DID URL fragment is a valid relative DID URL.  Keeping the Root
      // method relative makes the whole genesis document portable: the DID
      // changes on its first did:webvh publication, while this reference does
      // not need rewriting.
      id: "#pass-1",
      type: "Multikey",
      controller: placeholderDid,
      publicKeyMultibase: args.root.multikey,
    }],
    authentication: ["#pass-1"],
    // "UDIWalletIssuer" lets a relying party discover, from this identity's
    // own DID document alone, which wallet backend issues OAuth/OID4VP
    // tokens on its behalf -- the same pattern atproto uses for PDS
    // discovery (its DID document's "#atproto_pds" / AtprotoPersonalDataServer
    // entry), applied to wallet discovery instead of data hosting.
    service: [
      ...(args.api ? [{ id: "#udi-wallet-issuer", type: "UDIWalletIssuer", serviceEndpoint: args.api }] : []),
      ...(args.service ?? []),
    ],
    ...(args.displayName ? { name: args.displayName } : {}),
  };
  // SCID creation is purely deterministic JCS + SHA-256 multihash, done by
  // didwebvh-ts: creating a portable provisional DID works offline.
  const created = await createLog({
    domain: `${args.username}.${args.domain}`,
    signer: new Ed25519Signer(args.sign),
    updateKeys: [args.sign.multikey],
    nextKeyHashes: [await nextKeyHash(args.nextSpare.multikey)],
    didDocument: didDocument as any,
    portable: true,
  });
  return created.log[0];
}

/**
 * Produces the one additional, signed entry required to move a portable
 * did:webvh log to a new web location.  The original entries are deliberately
 * returned untouched: rewriting any historical entry would break its entry
 * hash and Data Integrity proof.
 *
 * This profile is for the Master-derived, permanent-pre-rotation identities
 * created by did.md.  Other did:webvh controllers can make the same standard
 * portability entry with their own current update-key implementation.
 */
export async function preparePortableImport(args: {
  entries: any[]; username: string; domain: string; masterSeed: Uint8Array;
}): Promise<{ entry: any; state: any; did: string; root: ControllerKey; nextSpareIndex: number }> {
  if (!Array.isArray(args.entries) || !args.entries.length) throw new Error("The DID log is empty.");
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(args.username)) throw new Error("Username must be a lowercase DNS-label-like identifier.");
  const first = args.entries[0];
  const latest = args.entries.at(-1);
  if (!first?.parameters || typeof first.parameters.scid !== "string") throw new Error("The DID log has no genesis SCID.");
  if (first.parameters.portable !== true) throw new Error("This DID was not created with portability enabled.");
  if (!latest?.state || typeof latest.state.id !== "string") throw new Error("The DID log has no current DID Document.");

  const parameters = args.entries.reduce((active, entry) => ({ ...active, ...entry.parameters }), {});
  if (parameters.deactivated === true) throw new Error("A deactivated DID cannot be imported.");
  if (!Array.isArray(parameters.updateKeys) || !Array.isArray(parameters.nextKeyHashes) || parameters.nextKeyHashes.length !== 1) {
    throw new Error("This importer requires exactly one active pre-rotation key commitment.");
  }
  if (parameters.witness && Object.keys(parameters.witness).length) {
    throw new Error("Importing a DID with active witnesses requires new witness proofs and is not yet supported.");
  }

  const root = await rootFromMasterSeed(args.masterSeed);
  if (!Array.isArray(first.parameters.updateKeys) || !first.parameters.updateKeys.includes(root.multikey)) {
    throw new Error("This Passphrase does not match the imported DID's genesis Root Key.");
  }
  if (!Array.isArray(latest.state.verificationMethod) || !latest.state.verificationMethod.some((method: any) => method?.publicKeyMultibase === root.multikey)) {
    throw new Error("The imported DID Document does not contain this Master-derived Root Key.");
  }

  const nextSpareIndex = args.entries.length - 1;
  const committedSpare = await spareFromMasterSeed(args.masterSeed, nextSpareIndex);
  if (!(await nextKeyHash(committedSpare.multikey) === parameters.nextKeyHashes[0])) {
    throw new Error("This Passphrase does not match the imported DID's current pre-rotation commitment.");
  }

  const oldDid = latest.state.id;
  const did = didFor(first.parameters.scid, args.username, args.domain);
  if (oldDid === did) throw new Error("This DID already uses the selected did.md location.");
  const state = retargetPortableDidDocument(latest.state, oldDid, did, args.username, args.domain);
  const prepared = await preparePreRotatedUpdate({
    entries: args.entries,
    state,
    masterSeed: args.masterSeed,
    currentSpareIndex: nextSpareIndex,
    domain: `${args.username}.${args.domain}`,
  });
  if (prepared.entry.state.id !== did) throw new Error("The moved DID does not match the requested location.");
  return { entry: prepared.entry, state: prepared.entry.state, did, root, nextSpareIndex: prepared.nextSpareIndex };
}

/**
 * Creates a portability entry with an arbitrary current Ed25519 update key.
 * A pre-rotated source must supply the already committed next key. Since an
 * arbitrary JWK carries no successor commitment, this move explicitly ends
 * pre-rotation; subsequent updates remain authorized by the imported key.
 */
export async function preparePortableJwkImport(args: {
  entries: any[]; username: string; domain: string; updateKey: ControllerKey;
}): Promise<{ entry: any; state: any; did: string; preRotationDisabled: boolean }> {
  if (!Array.isArray(args.entries) || !args.entries.length) throw new Error("The DID log is empty.");
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(args.username)) throw new Error("Username must be a lowercase DNS-label-like identifier.");
  const first = args.entries[0];
  const latest = args.entries.at(-1);
  if (!first?.parameters || typeof first.parameters.scid !== "string") throw new Error("The DID log has no genesis SCID.");
  if (first.parameters.portable !== true) throw new Error("This DID was not created with portability enabled.");
  if (!latest?.state || typeof latest.state.id !== "string" || typeof latest.versionId !== "string") throw new Error("The DID log has no current DID Document.");
  const parameters = args.entries.reduce((active, entry) => ({ ...active, ...entry.parameters }), {});
  if (parameters.deactivated === true) throw new Error("A deactivated DID cannot be imported.");
  if (!Array.isArray(parameters.updateKeys) || !Array.isArray(parameters.nextKeyHashes)) throw new Error("The DID log has invalid update-key parameters.");
  if (parameters.witness && Object.keys(parameters.witness).length) {
    throw new Error("Importing a DID with active witnesses requires new witness proofs and is not yet supported.");
  }

  const usesPreRotation = parameters.nextKeyHashes.length > 0;
  if (usesPreRotation) {
    if (!parameters.nextKeyHashes.includes(await nextKeyHash(args.updateKey.multikey))) {
      throw new Error("This JWK is not a key committed for the next pre-rotated update.");
    }
  } else if (!parameters.updateKeys.includes(args.updateKey.multikey)) {
    throw new Error("This JWK is not a current DID Log update key.");
  }

  const oldDid = latest.state.id;
  const did = didFor(first.parameters.scid, args.username, args.domain);
  if (oldDid === did) throw new Error("This DID already uses the selected did.md location.");
  const state = retargetPortableDidDocument(latest.state, oldDid, did, args.username, args.domain);
  const result = await updateLog({
    log: args.entries,
    signer: new Ed25519Signer(args.updateKey),
    // Ends pre-rotation when it was active: an arbitrary JWK carries no
    // successor commitment.
    ...(usesPreRotation ? { updateKeys: [args.updateKey.multikey], nextKeyHashes: [] } : {}),
    domain: `${args.username}.${args.domain}`,
    ...optionsFromDocument(state),
  } as any);
  const entry = result.log.at(-1)!;
  return { entry, state: entry.state, did, preRotationDisabled: usesPreRotation };
}

function retargetPortableDidDocument(source: any, oldDid: string, did: string, username: string, domain: string): any {
  const replace = (value: any): any => {
    if (typeof value === "string") return value.split(oldDid).join(did);
    if (Array.isArray(value)) return value.map(replace);
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, replace(item)]));
    return value;
  };
  const state = replace(source);
  state.id = did;
  const aliases = state.alsoKnownAs === undefined ? [] : state.alsoKnownAs;
  if (!Array.isArray(aliases) || !aliases.every(value => typeof value === "string")) throw new Error("The imported DID Document has an invalid alsoKnownAs property.");
  state.alsoKnownAs = [...new Set([...aliases, oldDid])];

  // These are did.md's two location-bound service conventions.  Other
  // service endpoints remain under controller control and are not guessed.
  if (Array.isArray(state.service)) {
    for (const service of state.service) {
      if (!service || typeof service !== "object") continue;
      if (service.id === "#files" || service.id === `${did}#files`) service.serviceEndpoint = `https://${username}.${domain}/`;
      if (service.id === "#whois" || service.id === `${did}#whois`) service.serviceEndpoint = `https://${username}.${domain}/whois.vp`;
    }
  }
  return state;
}

/**
 * A complete DID Document, expressed as didwebvh-ts update options. The
 * library builds each new state from the previous one plus these options
 * (verification methods, relationships, services, aliases), so every property
 * an update may change is listed here.
 */
function optionsFromDocument(state: any) {
  const isRelationship = (value: unknown) => Array.isArray(value) ? value : undefined;
  return {
    context: state["@context"],
    verificationMethods: Array.isArray(state.verificationMethod) ? state.verificationMethod : [],
    authentication: isRelationship(state.authentication),
    assertionMethod: isRelationship(state.assertionMethod),
    keyAgreement: isRelationship(state.keyAgreement),
    services: Array.isArray(state.service) ? state.service : [],
    alsoKnownAs: isRelationship(state.alsoKnownAs),
  };
}

/**
 * One pre-rotated update entry, signed by the key the log committed to (Spare
 * `currentSpareIndex`), committing to the next Spare. `state` is the complete
 * new DID Document; `domain` (optional) moves the DID to a new location.
 */
export async function preparePreRotatedUpdate(args: {
  entries: any[]; state: any; masterSeed: Uint8Array; currentSpareIndex: number; domain?: string;
}): Promise<{ entry: any; nextSpare: ControllerKey; nextSpareIndex: number }> {
  const parameters = args.entries.reduce((active, entry) => ({ ...active, ...entry.parameters }), {} as any);
  if (!Array.isArray(parameters.nextKeyHashes) || parameters.nextKeyHashes.length !== 1) {
    throw new Error("This identity does not have exactly one active Spare Key commitment.");
  }
  const currentSpare = await spareFromMasterSeed(args.masterSeed, args.currentSpareIndex);
  if (!parameters.nextKeyHashes.includes(await nextKeyHash(currentSpare.multikey))) {
    throw new Error("This Passphrase does not match the public pre-rotation commitment.");
  }
  const nextSpareIndex = args.currentSpareIndex + 1;
  const nextSpare = await spareFromMasterSeed(args.masterSeed, nextSpareIndex);
  const result = await updateLog({
    log: args.entries,
    signer: new Ed25519Signer(currentSpare),
    updateKeys: [currentSpare.multikey],
    nextKeyHashes: [await nextKeyHash(nextSpare.multikey)],
    ...(args.domain ? { domain: args.domain } : {}),
    ...optionsFromDocument(args.state),
  } as any);
  return { entry: result.log.at(-1), nextSpare, nextSpareIndex };
}
