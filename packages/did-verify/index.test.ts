import { afterEach, expect, test } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { jwkThumbprint, stableSubject, verifyIdTokenSignature } from "./index.ts";
import { createVhLog, keyFromPrivateKey, serializeVhLog, withLocation } from "../vh/src/index.ts";

function token(privateKey: Uint8Array, includeJwk = true, header: Record<string, unknown> = {}) {
  const jwk: JsonWebKey = { kty: "OKP", crv: "Ed25519", x: Buffer.from(ed25519.getPublicKey(privateKey)).toString("base64url") };
  const encodedHeader = Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "JWT", ...header, ...(includeJwk ? { jwk } : {}) })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ sub: "test" })).toString("base64url");
  const signature = ed25519.sign(new TextEncoder().encode(`${encodedHeader}.${payload}`), privateKey);
  return `${encodedHeader}.${payload}.${Buffer.from(signature).toString("base64url")}`;
}

// A real, signed did:vh log whose #pass-1 key is `privateKey`, published at `host`.
async function realLog(privateKey: Uint8Array, host = "alice.did.md") {
  const key = keyFromPrivateKey(privateKey);
  return createVhLog({
    signer: key, updateKeys: [key.multikey],
    document: did => withLocation({
      "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"], id: did,
      verificationMethod: [{ id: "#pass-1", type: "Multikey", controller: did, publicKeyMultibase: key.multikey }], authentication: ["#pass-1"],
    }, did, `https://${host}`),
  });
}

test("verifies an embedded Ed25519 JWK and returns its RFC 7638 thumbprint", async () => {
  const privateKey = ed25519.utils.randomSecretKey();
  const verified = await verifyIdTokenSignature(token(privateKey));
  expect(verified.method).toBe("jwk");
  expect(verified.sub).toBe(await jwkThumbprint(verified.publicKeyJwk));
});

test("rejects tampering and a missing JWK", async () => {
  const privateKey = ed25519.utils.randomSecretKey();
  const jwt = token(privateKey);
  const [header, payload, signature] = jwt.split(".");
  const changedPayload = Buffer.from(JSON.stringify({ sub: "tampered" })).toString("base64url");
  await expect(verifyIdTokenSignature(`${header}.${changedPayload}.${signature}`)).rejects.toThrow("signature");
  await expect(verifyIdTokenSignature(token(privateKey, false))).rejects.toThrow("jwk header missing");
});

const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });

const sources = (log: string, seen: string[] = []) => ({
  watchers: ["https://did.md"],
  fetch: (async (url: string | URL) => { seen.push(String(url)); return new Response(log, { status: 200 }); }) as typeof fetch,
});

test("resolves and verifies a did:vh kid-only token from the verifier's watchers (dito's real shape, no embedded jwk)", async () => {
  const privateKey = ed25519.utils.randomSecretKey();
  const created = await realLog(privateKey);
  const did = created.did;
  const jwt = token(privateKey, false, { kid: `${did}#pass-1` });
  const seen: string[] = [];
  const verified = await verifyIdTokenSignature(jwt, "did.md", sources(serializeVhLog(created.log), seen));
  expect(seen).toEqual([expect.stringContaining(`https://did.md/log?scid=${did.slice("did:vh:".length)}`)]);
  expect(verified.method).toBe("did-vh");
  expect(verified.sub).toBe(did);
});

test("rejects a did:vh whose published log does not validate (tampered document)", async () => {
  const privateKey = ed25519.utils.randomSecretKey();
  const created = await realLog(privateKey);
  const forged = JSON.parse(JSON.stringify(created.log));
  forged[0].state.verificationMethod[0].publicKeyMultibase = keyFromPrivateKey(ed25519.utils.randomSecretKey()).multikey;
  const jwt = token(privateKey, false, { kid: `${created.did}#pass-1` });
  await expect(verifyIdTokenSignature(jwt, "did.md", sources(serializeVhLog(forged)))).rejects.toThrow();
});

test("rejects a did:vh token whose document names no place under the allowed identity domain", async () => {
  const privateKey = ed25519.utils.randomSecretKey();
  const created = await realLog(privateKey, "evil.example");
  const jwt = token(privateKey, false, { kid: `${created.did}#pass-1` });
  await expect(verifyIdTokenSignature(jwt, "did.md", sources(serializeVhLog(created.log)))).rejects.toThrow("accepted issuer domain");
});

test("a did:vh token needs a verifier with watchers: the token cannot choose where its log is", async () => {
  const privateKey = ed25519.utils.randomSecretKey();
  const created = await realLog(privateKey);
  const jwt = token(privateKey, false, { kid: `${created.did}?src=https://evil.example#pass-1` });
  globalThis.fetch = (async () => { throw new Error("must not fetch"); }) as typeof fetch;
  await expect(verifyIdTokenSignature(jwt, "did.md")).rejects.toThrow(/watchers/);
  const kid = `did:web:alice.did.md#pass-1`;
  await expect(verifyIdTokenSignature(token(privateKey, false, { kid }), "did.md", sources(""))).rejects.toThrow();
});

test("RFC 7638 section 3.1 RSA example", async () => {
  // The canonical input and expected digest published in RFC 7638.
  const canonical = '{"e":"AQAB","kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiF_9iX2Gf7E7T3zXHIFU0YJ8Xv7Zx7b5u2xq9H3rJ1Z1"}';
  const jwk = JSON.parse(canonical) as JsonWebKey;
  const expected = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical))).toString("base64url");
  expect(await jwkThumbprint(jwk)).toBe(expected);
});

test("stableSubject: a did:vh DID is its SCID already (nothing in it moves)", async () => {
  const created = await realLog(ed25519.utils.randomSecretKey());
  expect(stableSubject(created.did)).toBe(created.did);
});

test("stableSubject leaves a JWK thumbprint, and anything else, unchanged", () => {
  expect(stableSubject("5Kz1u3Vq0fMw9y2m4a7mQ0aVJ3d1x8Z6bq0wq2c3XyA")).toBe("5Kz1u3Vq0fMw9y2m4a7mQ0aVJ3d1x8Z6bq0wq2c3XyA");
  expect(stableSubject("did:web:example.com")).toBe("did:web:example.com");
});
