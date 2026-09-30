import { ed25519 } from "@noble/curves/ed25519.js";
import {
  AbstractCrypto,
  MultibaseEncoding,
  multibaseEncode,
  prepareDataForSigning,
  type SigningInput,
  type SigningOutput,
  type Verifier,
} from "didwebvh-ts";

/** An Ed25519 key pair in did:webvh terms: raw 32-byte seed + its multikey. */
export type Ed25519Key = { privateKey: Uint8Array; multikey: string };

/** did:key-style multikey (`z6Mk…`) for a raw Ed25519 public key. */
export function multikeyFromPublicKey(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) throw new Error("An Ed25519 public key must be 32 bytes.");
  return multibaseEncode(new Uint8Array([0xed, 0x01, ...publicKey]), MultibaseEncoding.BASE58_BTC);
}

/** Build a key from a raw 32-byte Ed25519 private key (seed). */
export function keyFromPrivateKey(privateKey: Uint8Array): Ed25519Key {
  if (privateKey.length !== 32) throw new Error("An Ed25519 private key must be 32 bytes.");
  const seed = new Uint8Array(privateKey);
  return { privateKey: seed, multikey: multikeyFromPublicKey(ed25519.getPublicKey(seed)) };
}

/**
 * The Signer didwebvh-ts asks for: signs `eddsa-jcs-2022` Data Integrity
 * proofs with an in-memory Ed25519 key. Also a Verifier, so one object can be
 * passed as both `signer` and `verifier`.
 */
export class Ed25519Signer extends AbstractCrypto {
  private readonly key: Ed25519Key;

  constructor(key: Ed25519Key) {
    super({ verificationMethod: { type: "Multikey", publicKeyMultibase: key.multikey } });
    this.key = key;
  }

  /** did:webvh proofs reference the (pre-)rotation key as a did:key URL. */
  getVerificationMethodId(): string {
    return `did:key:${this.key.multikey}#${this.key.multikey}`;
  }

  async sign(input: SigningInput): Promise<SigningOutput> {
    const data = await prepareDataForSigning(input.document, input.proof);
    const signature = ed25519.sign(data, this.key.privateKey);
    return { proofValue: multibaseEncode(signature, MultibaseEncoding.BASE58_BTC) };
  }

  verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    return Promise.resolve(ed25519.verify(signature, message, publicKey));
  }
}

/** Verifier for resolving/validating logs (didwebvh-ts requires one). */
export const ed25519Verifier: Verifier = {
  verify: (signature, message, publicKey) => Promise.resolve(ed25519.verify(signature, message, publicKey)),
};
