/**
 * The hash constructions of VH-Log: base58btc(multihash(SHA-256, JCS(value))) for
 * the SCID and the entry hash, and base58btc(multihash(SHA-256, multikey)) for a
 * pre-rotation commitment. SHA-256 is the only algorithm `did:vh:1.0` permits.
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { base58btc } from "./base58.ts";
export { base58btc };
import { canonicalize } from "./jcs.ts";

const SHA2_256 = 0x12;


/** Multihash of `data` with SHA-256: code 0x12, length 0x20, digest. */
export function multihashSha256(data: Uint8Array): Uint8Array {
  const digest = sha256(data);
  const out = new Uint8Array(2 + digest.length);
  out[0] = SHA2_256;
  out[1] = digest.length;
  out.set(digest, 2);
  return out;
}

const utf8 = (text: string) => new TextEncoder().encode(text);

/** base58btc(multihash(JCS(value))): the SCID and entry-hash function. */
export function jcsHash(value: unknown): string {
  return base58btc(multihashSha256(utf8(canonicalize(value))));
}

/** The `nextKeyHashes` commitment to a multikey: no JSON, no JCS, the multikey string itself. */
export function keyHash(multikey: string): string {
  return base58btc(multihashSha256(utf8(multikey)));
}
