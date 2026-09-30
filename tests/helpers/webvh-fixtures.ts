// Test-only helpers for hand-building did:webvh entries (negative cases that
// must bypass the library's own builders). Production code has no need for
// these: didwebvh-ts computes every hash.
import { MultibaseEncoding, multibaseDecode, multibaseEncode } from "didwebvh-ts";
import { jcs } from "../../packages/wallet/src/did-webvh.ts";

/** Base58btc SHA-256 multihash of a string, or of the JCS form of an object. */
export async function multihash(value: string | object): Promise<string> {
  const canonical = typeof value === "string" ? value : jcs(value);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical)));
  return multibaseEncode(new Uint8Array([0x12, 0x20, ...digest]), MultibaseEncoding.BASE58_BTC).slice(1);
}

/** Raw bytes of a base58btc string (no multibase prefix). */
export function base58Decode(value: string): Uint8Array {
  return multibaseDecode(`z${value}`).bytes;
}
