// Test-only: a small signed did:vh log that names `host` as its place (`https://<host>`), with the keys that made it.
import { createVhLog, keyFromPrivateKey, keyHash, withLocation } from "../../packages/vh/src/index.ts";

export async function vhLogAt(host: string) {
  const key = keyFromPrivateKey(crypto.getRandomValues(new Uint8Array(32)));
  const next = keyFromPrivateKey(crypto.getRandomValues(new Uint8Array(32)));
  const created = await createVhLog({
    signer: key, updateKeys: [key.multikey], nextKeyHashes: [keyHash(next.multikey)],
    document: did => withLocation({
      "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"], id: did,
      verificationMethod: [{ id: `${did}#k`, type: "Multikey", controller: did, publicKeyMultibase: key.multikey }], authentication: [`${did}#k`],
    }, did, `https://${host}`),
  });
  return { ...created, key, next };
}
