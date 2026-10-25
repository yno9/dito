import { ed25519 } from "@noble/curves/ed25519.js";
import { multibaseBase58 } from "./base58.ts";

/** An Ed25519 key pair: the raw 32-byte seed and its multikey (`z6Mk…`). */
export type Ed25519Key = { privateKey: Uint8Array; multikey: string };

/** did:key-style multikey (`z6Mk…`) for a raw Ed25519 public key. */
export function multikeyFromPublicKey(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) throw new Error("An Ed25519 public key must be 32 bytes.");
  return multibaseBase58(new Uint8Array([0xed, 0x01, ...publicKey]));
}

/** Build a key from a raw 32-byte Ed25519 private key (seed). */
export function keyFromPrivateKey(privateKey: Uint8Array): Ed25519Key {
  if (privateKey.length !== 32) throw new Error("An Ed25519 private key must be 32 bytes.");
  const seed = new Uint8Array(privateKey);
  return { privateKey: seed, multikey: multikeyFromPublicKey(ed25519.getPublicKey(seed)) };
}
