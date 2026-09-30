import { multihash, base58Decode } from "./helpers/webvh-fixtures.ts";
import { Ed25519Signer, createLog, keyFromPrivateKey, serializeLog } from "../packages/webvh/src/index.ts";
import { afterEach, expect, test } from "bun:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  buildGenesis,
  controllerFromEd25519Jwk,
  createKeyAuthorizationCredentialWire,
  createIdentityMaterial,
  deriveWalletSecret,
  jcs,
  preparePortableImport,
  preparePortableJwkImport,
  preparePreRotatedUpdate,
  rootFromMasterSeed,
  seedFromMnemonic,
  spareFromMasterSeed,
  verifyRequestObjectJws,
} from "../packages/wallet/src/did-webvh.ts";

const encoder = new TextEncoder();

async function sha256(value: string) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

test("one Master mnemonic deterministically derives Root and every hardened pre-rotation key", async () => {
  const identity = await createIdentityMaterial();
  const masterSeed = seedFromMnemonic(identity.masterMnemonic, "Master mnemonic");
  const root = await rootFromMasterSeed(masterSeed);
  const spare0 = await spareFromMasterSeed(masterSeed, 0);
  const spare1 = await spareFromMasterSeed(masterSeed, 1);

  expect(identity.masterMnemonic.split(" ")).toHaveLength(24);
  expect(root.multikey).toBe(identity.root.multikey);
  expect(spare0.multikey).toBe(identity.nextSpare.multikey);
  expect(spare0.multikey).not.toBe(root.multikey);
  expect(spare1.multikey).not.toBe(spare0.multikey);
  expect(identity.sign.multikey).toBe(identity.root.multikey);
  expect(identity.nextSpareIndex).toBe(0);
});

test("deriveWalletSecret is deterministic per Root key, purpose and context, and never touches its input", async () => {
  const a = await createIdentityMaterial();
  const b = await createIdentityMaterial();

  const first = deriveWalletSecret(a.root.privateKey, "biset:mimi-vault-room:v1", "https://mimi.example/");
  const again = deriveWalletSecret(a.root.privateKey, "biset:mimi-vault-room:v1", "https://mimi.example/");
  expect([...first]).toEqual([...again]);
  expect(first).toHaveLength(32);

  // A different Root key -- i.e. a different identity, which is all a
  // relying party's own devices actually share -- must not converge on the
  // same value: reproducibility only holds for devices that hold this
  // identity's own Root key, never for an outside observer.
  const otherIdentity = deriveWalletSecret(b.root.privateKey, "biset:mimi-vault-room:v1", "https://mimi.example/");
  expect([...otherIdentity]).not.toEqual([...first]);

  // purpose and context are domain separators: two RPs (or two uses within
  // one RP) asking for different labels must never collide, even under the
  // same Root key.
  const otherPurpose = deriveWalletSecret(a.root.privateKey, "biset:other-purpose:v1", "https://mimi.example/");
  expect([...otherPurpose]).not.toEqual([...first]);
  const otherContext = deriveWalletSecret(a.root.privateKey, "biset:mimi-vault-room:v1", "https://other.example/");
  expect([...otherContext]).not.toEqual([...first]);
  const noContext = deriveWalletSecret(a.root.privateKey, "biset:mimi-vault-room:v1", undefined);
  expect([...noContext]).not.toEqual([...first]);

  // The private key itself is only ever HKDF input keying material -- never
  // mutated, and no accidental echo of it into the output.
  const rootCopy = a.root.privateKey.slice();
  deriveWalletSecret(a.root.privateKey, "biset:mimi-vault-room:v1", "https://mimi.example/");
  expect([...a.root.privateKey]).toEqual([...rootCopy]);
});

test("a provisional did.invalid genesis is created entirely in the browser", async () => {
  const identity = await createIdentityMaterial();
  const genesis = await buildGenesis({
    username: "did", domain: "invalid", root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare,
  });
  expect(genesis.state.id).toMatch(/^did:webvh:[1-9A-HJ-NP-Za-km-z]{46}:did\.invalid$/);
  expect(genesis.parameters.scid).toBe(genesis.state.id.split(":")[2]);
  expect(genesis.parameters.portable).toBe(true);
  expect(genesis.state.verificationMethod[0].id).toBe("#pass-1");
  expect(genesis.state.authentication).toEqual(["#pass-1"]);
  expect(genesis.state.service).toEqual([]);
});

// Wallet discovery (atproto-style: a relying party resolves the user's own
// DID document to find which backend issues that identity's OAuth tokens,
// the same pattern atproto uses for #atproto_pds/AtprotoPersonalDataServer
// PDS discovery). `api` was an unused buildGenesis parameter before this;
// supplying it now publishes the issuer as a "#udi-wallet-issuer" service.
test("buildGenesis publishes a UDIWalletIssuer service entry when api is supplied", async () => {
  const identity = await createIdentityMaterial();
  const genesis = await buildGenesis({
    username: "alice", domain: "did.md", root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare,
    api: "https://api.did.md",
  });
  expect(genesis.state.service).toEqual([{ id: "#udi-wallet-issuer", type: "UDIWalletIssuer", serviceEndpoint: "https://api.did.md" }]);
});

test("buildGenesis omits the UDIWalletIssuer entry when api is not supplied (existing callers unaffected)", async () => {
  const identity = await createIdentityMaterial();
  const genesis = await buildGenesis({
    username: "bob", domain: "did.md", root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare,
  });
  expect(genesis.state.service).toEqual([]);
});

test("buildGenesis orders the UDIWalletIssuer entry before any caller-supplied service entries", async () => {
  const identity = await createIdentityMaterial();
  const genesis = await buildGenesis({
    username: "carol", domain: "did.md", root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare,
    api: "https://api.did.md",
    service: [{ id: "#oauth-redirect", type: "OAuthRedirectTarget", serviceEndpoint: "https://t.biset.md/wallet/callback" }],
  });
  expect(genesis.state.service).toEqual([
    { id: "#udi-wallet-issuer", type: "UDIWalletIssuer", serviceEndpoint: "https://api.did.md" },
    { id: "#oauth-redirect", type: "OAuthRedirectTarget", serviceEndpoint: "https://t.biset.md/wallet/callback" },
  ]);
});

test("the Master-derived Spare creates a valid pre-rotated update and commits its successor", async () => {
  const identity = await createIdentityMaterial();
  const genesis = await buildGenesis({ username: "proof-test", domain: "did.md", root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare });
  const state = genesis.state;
  const result = await preparePreRotatedUpdate({
    entries: [genesis],
    state,
    masterSeed: identity.masterSeed,
    currentSpareIndex: 0,
  });
  const spare1 = await spareFromMasterSeed(identity.masterSeed, 1);

  expect(result.entry.parameters.updateKeys).toEqual([identity.nextSpare.multikey]);
  expect(result.entry.parameters.nextKeyHashes).toEqual([await multihash(spare1.multikey)]);
  expect(result.nextSpare.multikey).toBe(spare1.multikey);
  expect(result.nextSpareIndex).toBe(1);

  const proof = result.entry.proof[0];
  const { proofValue, ...proofConfig } = proof;
  const unsigned = { versionId: result.entry.versionId, versionTime: result.entry.versionTime, parameters: result.entry.parameters, state: result.entry.state };
  const payload = new Uint8Array(64);
  payload.set(await sha256(jcs(proofConfig)));
  payload.set(await sha256(jcs(unsigned)), 32);
  expect(ed25519.verify(base58Decode(proofValue.slice(1)), payload, base58Decode(identity.nextSpare.multikey.slice(1)).slice(2))).toBe(true);
});

test("a portable import preserves history and appends a signed did.md rename entry", async () => {
  const identity = await createIdentityMaterial();
  const genesis = await buildGenesis({
    username: "old", domain: "example", root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare,
    service: [{ id: "#files", type: "relativeRef", serviceEndpoint: "https://old.example/" }],
  });
  const entries = [genesis];
  const oldDid = genesis.state.id;
  const scid = genesis.parameters.scid;

  const moved = await preparePortableImport({ entries, username: "alice", domain: "did.md", masterSeed: identity.masterSeed });
  const newDid = `did:webvh:${scid}:alice.did.md`;

  expect(entries[0]!.state.id).toBe(oldDid);
  expect(moved.did).toBe(newDid);
  expect(moved.state.id).toBe(newDid);
  expect(moved.state.alsoKnownAs).toEqual([oldDid]);
  expect(moved.state.verificationMethod[0].id).toBe("#pass-1");
  expect(moved.state.verificationMethod[0].controller).toBe(newDid);
  expect(moved.state.service[0].serviceEndpoint).toBe("https://alice.did.md/");
  expect(moved.entry.state).toEqual(moved.state);
  expect(moved.entry.parameters.updateKeys).toEqual([identity.nextSpare.multikey]);
});

test("a private Ed25519 JWK can sign a portable import without being a Master mnemonic", async () => {
  const identity = await createIdentityMaterial();
  const b64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const updateKey = controllerFromEd25519Jwk({
    kty: "OKP", crv: "Ed25519", d: b64url(identity.nextSpare.privateKey),
    x: b64url(base58Decode(identity.nextSpare.multikey.slice(1)).slice(2)),
  });
  const genesis = await buildGenesis({ username: "old", domain: "example", root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare });
  const scid = genesis.parameters.scid;
  const moved = await preparePortableJwkImport({ entries: [genesis], username: "jwk", domain: "did.md", updateKey });

  expect(moved.entry.state.id).toBe(`did:webvh:${scid}:jwk.did.md`);
  expect(moved.entry.parameters.updateKeys).toEqual([identity.nextSpare.multikey]);
  expect(moved.entry.parameters.nextKeyHashes).toEqual([]);
  expect(moved.preRotationDisabled).toBe(true);
  updateKey.privateKey.fill(0);
});

test("Wallet issues an audience-bound generic key credential signed by both Root and current Sign", async () => {
  const identity = await createIdentityMaterial();
  const did = "did:webvh:QmNf4Y7DyYWTZcrMdQMwftYe5JmcKXfPrxpqwriHa3A7w5:wallet-device.did.md";
  const wire = await createKeyAuthorizationCredentialWire({
    issuer: did, audience: "client_test", subject: "urn:uuid:11111111-1111-4111-8111-111111111111",
    generation: "1-QmNf4Y7DyYWTZcrMdQMwftYe5JmcKXfPrxpqwriHa3A7w5",
    publicKey: { type: "Multikey", publicKeyMultibase: identity.sign.multikey }, purposes: ["signing"],
    issuedAt: "2026-09-09T00:00:00.000Z", expiresAt: "2026-10-09T00:00:00.000Z",
    rootPrivateKey: identity.root.privateKey,
    signPrivateKey: identity.sign.privateKey,
  });
  const padded = wire.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - wire.length % 4) % 4);
  const value = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(padded), byte => byte.charCodeAt(0))));
  const signingBytes = encoder.encode(jcs({
    label: "did.md/key-authorization/v1", type: value.type, version: value.version,
    issuer: value.issuer, audience: value.audience, subject: value.subject, generation: value.generation,
    publicKey: value.publicKey, purposes: value.purposes, issuedAt: value.issuedAt, expiresAt: value.expiresAt,
  }));
  const sig = (input: string) => Uint8Array.from(atob(input.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - input.length % 4) % 4)), byte => byte.charCodeAt(0));

  expect(value.version).toBe(1);
  expect(value.issuer).toBe(did);
  expect(value.audience).toBe("client_test");
  expect(ed25519.verify(sig(value.rootSignature), signingBytes, ed25519.getPublicKey(identity.root.privateKey))).toBe(true);
  expect(ed25519.verify(sig(value.signSignature), signingBytes, ed25519.getPublicKey(identity.sign.privateKey))).toBe(true);
});

// PLAN6: a relying party (biset/oidc-bridge) authenticates its Authorization
// Request with a JAR (RFC 9101) signed by its own did:webvh key, rather than
// a DCR-issued client_id/secret. verifyRequestObjectJws is the wallet-UI-side
// verifier (client/did-webvh.ts, browser-safe -- see packages/did-verify for
// the equivalent used by oidc-bridge's Node/Bun backend).
function base64url(bytes: Uint8Array): string {
  let binary = ""; for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
// A real, signed RP log (t.biset.md) whose #key-1 is `privateKey`.
async function rpLog(privateKey: Uint8Array, services: unknown[] = []) {
  const key = keyFromPrivateKey(privateKey);
  return createLog({
    domain: "t.biset.md", signer: new Ed25519Signer(key), updateKeys: [key.multikey],
    verificationMethods: [{ id: "#key-1", type: "Multikey", publicKeyMultibase: key.multikey }], authentication: ["#key-1"],
    services: services as never,
  });
}

function signedRequestObject(privateKey: Uint8Array, kid: string, payload: Record<string, unknown>) {
  const header = base64url(new TextEncoder().encode(JSON.stringify({ alg: "EdDSA", typ: "JWT", kid })));
  const body = base64url(new TextEncoder().encode(JSON.stringify(payload)));
  const signature = ed25519.sign(new TextEncoder().encode(`${header}.${body}`), privateKey);
  return `${header}.${body}.${base64url(signature)}`;
}

const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });

test("verifyRequestObjectJws resolves the RP's did:webvh key and returns its service array", async () => {
  const privateKey = ed25519.utils.randomSecretKey();
  const services = [{ id: "#oauth-redirect", type: "OAuthRedirectTarget", serviceEndpoint: "https://t.biset.md/wallet/callback" }];
  const created = await rpLog(privateKey, services);
  const rpDid = created.did;
  const jwt = signedRequestObject(privateKey, `${rpDid}#key-1`, { hello: "world" });
  globalThis.fetch = (async (url: string | URL) => {
    expect(String(url)).toBe("https://t.biset.md/.well-known/did.jsonl");
    return new Response(serializeLog(created.log), { status: 200 });
  }) as typeof fetch;
  const result = await verifyRequestObjectJws(jwt);
  expect(result.rpDid).toBe(rpDid);
  expect(result.payload).toEqual({ hello: "world" });
  // (didwebvh-ts also adds its implicit #files/#whois services when it builds the document.)
  for (const service of services) expect(result.service).toContainEqual(service);
});

test("verifyRequestObjectJws rejects a tampered payload", async () => {
  const privateKey = ed25519.utils.randomSecretKey();
  const created = await rpLog(privateKey);
  const jwt = signedRequestObject(privateKey, `${created.did}#key-1`, { state: "original" });
  const [header, , signature] = jwt.split(".");
  const tampered = `${header}.${base64url(new TextEncoder().encode(JSON.stringify({ state: "tampered" })))}.${signature}`;
  globalThis.fetch = (async () => new Response(serializeLog(created.log), { status: 200 })) as typeof fetch;
  await expect(verifyRequestObjectJws(tampered)).rejects.toThrow("signature is invalid");
});

test("verifyRequestObjectJws rejects an RP log that does not validate (forged document key)", async () => {
  const privateKey = ed25519.utils.randomSecretKey();
  const created = await rpLog(privateKey);
  const forged = JSON.parse(JSON.stringify(created.log));
  forged[0].state.verificationMethod[0].publicKeyMultibase = keyFromPrivateKey(ed25519.utils.randomSecretKey()).multikey;
  const jwt = signedRequestObject(privateKey, `${created.did}#key-1`, {});
  globalThis.fetch = (async () => new Response(serializeLog(forged), { status: 200 })) as typeof fetch;
  await expect(verifyRequestObjectJws(jwt)).rejects.toThrow();
});

test("verifyRequestObjectJws rejects a percent-encoded domain smuggling a URL fragment (SSRF)", async () => {
  const privateKey = ed25519.utils.randomSecretKey();
  const scid = (await rpLog(privateKey)).did.split(":")[2];
  const rpDid = `did:webvh:${scid}:evil.com%23.did.md`;
  const jwt = signedRequestObject(privateKey, `${rpDid}#key-1`, {});
  globalThis.fetch = (async () => { throw new Error("must not fetch an out-of-charset domain"); }) as typeof fetch;
  await expect(verifyRequestObjectJws(jwt)).rejects.toThrow("fully qualified DNS name");
});
