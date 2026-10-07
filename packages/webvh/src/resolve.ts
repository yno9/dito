import { didToLogUrl } from "./url.ts";
import { parseLog, resolveLog } from "./log.ts";
import { publicKeyFromMultikey } from "./proof.ts";
import type { DIDLog } from "./log.ts";

/**
 * Resolve a did:webvh DID over HTTPS: fetch its `did.jsonl`, validate the WHOLE
 * log with didwebvh-ts, and return the latest DID Document. Callers apply
 * their own policy (allowed domains, caching) before calling; the URL comes
 * from the strict parser in url.ts.
 */
export async function resolveDidWebvh(did: string, options: { fetch?: typeof fetch } = {}) {
  const doFetch = options.fetch ?? fetch;
  const logUrl = didToLogUrl(did);
  const response = await doFetch(logUrl);
  if (!response.ok) throw new Error(`did:webvh log fetch failed: ${response.status}`);
  const text = await response.text();
  const log = parseLog(text.endsWith("\n") ? text : `${text}\n`);
  const witnessProofs = usesWitnesses(log) ? await fetchWitnessProofs(logUrl, doFetch) : undefined;
  const resolved = await resolveLog(log, witnessProofs ? { witnessProofs } : {});
  if (resolved.doc.id !== did) throw new Error("did:webvh log does not describe the expected DID");
  return resolved;
}

/** True if any entry configures witnesses (then `did-witness.json` is needed to validate). */
export function usesWitnesses(log: DIDLog): boolean {
  return log.some(entry => (entry.parameters.witness?.witnesses?.length ?? 0) > 0);
}

/** `did-witness.json` lives next to `did.jsonl`. */
export async function fetchWitnessProofs(logUrl: string, doFetch: typeof fetch = fetch) {
  const response = await doFetch(logUrl.replace(/did\.jsonl$/, "did-witness.json"));
  if (!response.ok) throw new Error(`did:webvh witness file fetch failed: ${response.status}`);
  const parsed = await response.json();
  if (!Array.isArray(parsed)) throw new Error("did-witness.json must be an array");
  return parsed as Parameters<typeof resolveLog>[1] extends infer O ? (O extends { witnessProofs?: infer W } ? NonNullable<W> : never) : never;
}

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
  if (!candidate || typeof candidate.publicKeyMultibase !== "string") throw new Error("did:webvh document has no matching authentication method");
  const key = publicKeyFromMultikey(candidate.publicKeyMultibase);
  if (!key) throw new Error("only Ed25519 multikeys are supported");
  return key;
}

/** The Root key did.md's wallet creates every identity with (buildGenesis). */
export const ROOT_KEY_FRAGMENT = "#pass-1";

/**
 * Whether the `authentication` method `verificationMethod` (absolute) may sign
 * the user in -- a wallet's capability or self-issued id_token. When the
 * document's authentication methods include its Root key (`#pass-1`, a did.md
 * identity), only the Root may: other authentication keys there were added for
 * relying parties (a messaging app's signing key, say) and must not be able to
 * act as the user everywhere. A document without one is some other wallet's,
 * whose key names are not assumed (PLAN1): any authentication method may.
 */
export function maySignIn(document: Record<string, any>, did: string, verificationMethod: string): boolean {
  const absolute = (id: unknown) => typeof id === "string" && id.startsWith("#") ? `${did}${id}` : id;
  const authentication = (Array.isArray(document.authentication) ? document.authentication : []).map(absolute);
  if (!authentication.includes(verificationMethod)) return false;
  const root = `${did}${ROOT_KEY_FRAGMENT}`;
  return !authentication.includes(root) || verificationMethod === root;
}
