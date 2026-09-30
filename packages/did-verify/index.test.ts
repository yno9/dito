import { afterEach, expect, test } from "bun:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { jwkThumbprint, verifyIdTokenSignature } from "./index.ts";
import { Ed25519Signer, createLog, keyFromPrivateKey, serializeLog } from "../webvh/src/index.ts";

function token(privateKey: Uint8Array, includeJwk = true, header: Record<string, unknown> = {}) {
  const jwk: JsonWebKey = { kty: "OKP", crv: "Ed25519", x: Buffer.from(ed25519.getPublicKey(privateKey)).toString("base64url") };
  const encodedHeader = Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "JWT", ...header, ...(includeJwk ? { jwk } : {}) })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ sub: "test" })).toString("base64url");
  const signature = ed25519.sign(new TextEncoder().encode(`${encodedHeader}.${payload}`), privateKey);
  return `${encodedHeader}.${payload}.${Buffer.from(signature).toString("base64url")}`;
}

// A real, signed did:webvh log whose #pass-1 key is `privateKey`.
async function realLog(privateKey: Uint8Array, domain = "alice.did.md") {
  const key = keyFromPrivateKey(privateKey);
  return createLog({
    domain, signer: new Ed25519Signer(key), updateKeys: [key.multikey],
    verificationMethods: [{ id: "#pass-1", type: "Multikey", publicKeyMultibase: key.multikey }], authentication: ["#pass-1"],
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

test("resolves and verifies a did:webvh kid-only token (dito's real shape, no embedded jwk)", async () => {
  const privateKey = ed25519.utils.randomSecretKey();
  const created = await realLog(privateKey);
  const did = created.did;
  const jwt = token(privateKey, false, { kid: `${did}#pass-1` });
  globalThis.fetch = (async (url: string | URL) => {
    expect(String(url)).toBe("https://alice.did.md/.well-known/did.jsonl");
    return new Response(serializeLog(created.log), { status: 200 });
  }) as typeof fetch;
  const verified = await verifyIdTokenSignature(jwt, "did.md");
  expect(verified.method).toBe("did-webvh");
  expect(verified.sub).toBe(did);
});

test("rejects a did:webvh whose published log does not validate (tampered document)", async () => {
  const privateKey = ed25519.utils.randomSecretKey();
  const created = await realLog(privateKey);
  const forged = JSON.parse(JSON.stringify(created.log));
  forged[0].state.verificationMethod[0].publicKeyMultibase = keyFromPrivateKey(ed25519.utils.randomSecretKey()).multikey;
  const jwt = token(privateKey, false, { kid: `${created.did}#pass-1` });
  globalThis.fetch = (async () => new Response(serializeLog(forged), { status: 200 })) as typeof fetch;
  await expect(verifyIdTokenSignature(jwt, "did.md")).rejects.toThrow();
});

test("rejects a did:webvh token whose kid domain is outside the allowed identity domain", async () => {
  const privateKey = ed25519.utils.randomSecretKey();
  const scid = (await realLog(privateKey)).did.split(":")[2];
  const kid = `did:webvh:${scid}:evil.example#pass-1`;
  const jwt = token(privateKey, false, { kid });
  globalThis.fetch = (async () => { throw new Error("must not fetch an out-of-domain DID"); }) as typeof fetch;
  await expect(verifyIdTokenSignature(jwt, "did.md")).rejects.toThrow("accepted issuer domain");
});

test("rejects a percent-encoded domain that would smuggle a URL fragment past the allowlist", async () => {
  const privateKey = ed25519.utils.randomSecretKey();
  // Decodes to "evil.com#.did.md": passes a naive `.endsWith(".did.md")`
  // string check, but "https://evil.com#.did.md/.well-known/did.jsonl"
  // fetches only "evil.com" (the rest becomes a URL fragment).
  const scid = (await realLog(privateKey)).did.split(":")[2];
  const kid = `did:webvh:${scid}:evil.com%23.did.md#pass-1`;
  const jwt = token(privateKey, false, { kid });
  globalThis.fetch = (async () => { throw new Error("must not fetch an out-of-domain DID"); }) as typeof fetch;
  await expect(verifyIdTokenSignature(jwt, "did.md")).rejects.toThrow("fully qualified DNS name");
});

test("RFC 7638 section 3.1 RSA example", async () => {
  // The canonical input and expected digest published in RFC 7638.
  const canonical = '{"e":"AQAB","kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiF_9iX2Gf7E7T3zXHIFU0YJ8Xv7Zx7b5u2xq9H3rJ1Z1"}';
  const jwk = JSON.parse(canonical) as JsonWebKey;
  const expected = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical))).toString("base64url");
  expect(await jwkThumbprint(jwk)).toBe(expected);
});
