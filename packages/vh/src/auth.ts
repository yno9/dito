/**
 * Which key of a resolved DID document may authenticate, and which of those may sign the user in.
 */
import { publicKeyFromMultikey } from "./proof.ts";

/**
 * The Ed25519 public key of the `authentication` verification method named
 * `verificationMethod` (an absolute `<did>#<fragment>`; relative ids in the
 * document are resolved against `did`). Throws if it is not an authentication
 * method or not an Ed25519 multikey.
 */
export function authenticationPublicKey(document: Record<string, any>, did: string, verificationMethod: string): Uint8Array {
  const methods = Array.isArray(document.verificationMethod) ? document.verificationMethod : [];
  const authentication = Array.isArray(document.authentication) ? document.authentication : [];
  const candidate = methods.find((value: any) => {
    if (!value || typeof value !== "object" || typeof value.id !== "string") return false;
    const absolute = value.id.startsWith("#") ? `${did}${value.id}` : value.id;
    return absolute === verificationMethod && (authentication.includes(absolute) || (value.id.startsWith("#") && authentication.includes(value.id)));
  });
  if (!candidate || typeof candidate.publicKeyMultibase !== "string") throw new Error("the DID document has no matching authentication method");
  const key = publicKeyFromMultikey(candidate.publicKeyMultibase);
  if (!key) throw new Error("only Ed25519 multikeys are supported");
  return key;
}

/** The Root key did.md's wallet creates every identity with. */
export const ROOT_KEY_FRAGMENT = "#pass-1";

/**
 * Whether the `authentication` method `verificationMethod` (absolute) may sign
 * the user in -- a wallet's capability or self-issued id_token. When the
 * document's authentication methods include its Root key (`#pass-1`, a did.md
 * identity), only the Root may: other authentication keys there were added for
 * relying parties (a messaging app's signing key, say) and must not be able to
 * act as the user everywhere. A document without one is some other wallet's,
 * whose key names are not assumed: any authentication method may.
 */
export function maySignIn(document: Record<string, any>, did: string, verificationMethod: string): boolean {
  const absolute = (id: unknown) => typeof id === "string" && id.startsWith("#") ? `${did}${id}` : id;
  const authentication = (Array.isArray(document.authentication) ? document.authentication : []).map(absolute);
  if (!authentication.includes(verificationMethod)) return false;
  const root = `${did}${ROOT_KEY_FRAGMENT}`;
  return !authentication.includes(root) || verificationMethod === root;
}
