/** base64url without padding (RFC 4648 §5), for JOSE values. Browser-safe: no Buffer. */

const BASE64URL = /^[A-Za-z0-9_-]+$/;

export function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decode a non-empty base64url value; `label` names it in the error. */
export function base64urlDecode(value: unknown, label: string): Uint8Array<ArrayBuffer> {
  if (typeof value !== "string" || !BASE64URL.test(value)) throw new Error(`${label} must be base64url.`);
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  let binary: string;
  try { binary = atob(padded); } catch { throw new Error(`${label} must be base64url.`); }
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

export function utf8Base64url(text: string): string {
  return base64url(new TextEncoder().encode(text));
}

export async function sha256Base64url(text: string): Promise<string> {
  return base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))));
}
