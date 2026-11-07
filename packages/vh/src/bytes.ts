/**
 * WebCrypto takes only ArrayBuffer-backed views (no SharedArrayBuffer). This
 * narrows a caller's Uint8Array without copying it, so secrets can still be wiped in place.
 */
export function arrayBufferBytes(value: Uint8Array, label: string): Uint8Array<ArrayBuffer> {
  if (!(value instanceof Uint8Array) || !(value.buffer instanceof ArrayBuffer)) throw new Error(`${label} must be an ArrayBuffer-backed Uint8Array.`);
  return value as Uint8Array<ArrayBuffer>;
}
