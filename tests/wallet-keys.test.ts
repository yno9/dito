import { afterEach, expect, test } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  createKeyAuthorizationCredentialWire,
  createIdentityMaterial,
  deriveWalletSecret,
  jcs,
  rootFromMasterSeed,
  seedFromMnemonic,
  spareFromMasterSeed,
} from "../packages/wallet/src/keys.ts";
import { createGenesisEntry, currentVhParameters, prepareLocationEntry, prepareUpdateEntry } from "../packages/wallet/src/vh-ops.ts";
import {
  createVhLog, keyFromPrivateKey, keyHash, locationsOf, resolveVhLog, serializeVhLog, verifyProofSignature, withLocation, type VhLogEntry,
} from "../packages/vh/src/index.ts";
import { resolveRpDocument, verifyRequestObjectJws } from "../client/request-object.ts";

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

  // A different Root key -- i.e. a different identity -- must not converge on the same value.
  const otherIdentity = deriveWalletSecret(b.root.privateKey, "biset:mimi-vault-room:v1", "https://mimi.example/");
  expect([...otherIdentity]).not.toEqual([...first]);

  // purpose and context are domain separators.
  const otherPurpose = deriveWalletSecret(a.root.privateKey, "biset:other-purpose:v1", "https://mimi.example/");
  expect([...otherPurpose]).not.toEqual([...first]);
  const otherContext = deriveWalletSecret(a.root.privateKey, "biset:mimi-vault-room:v1", "https://other.example/");
  expect([...otherContext]).not.toEqual([...first]);
  const noContext = deriveWalletSecret(a.root.privateKey, "biset:mimi-vault-room:v1", undefined);
  expect([...noContext]).not.toEqual([...first]);

  // The private key itself is only ever HKDF input keying material -- never mutated.
  const rootCopy = a.root.privateKey.slice();
  deriveWalletSecret(a.root.privateKey, "biset:mimi-vault-room:v1", "https://mimi.example/");
  expect([...a.root.privateKey]).toEqual([...rootCopy]);
});

test("a genesis with no host is created entirely in the browser, and names no place", async () => {
  const identity = await createIdentityMaterial();
  const genesis = await createGenesisEntry({ root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare });
  expect(genesis.state.id).toMatch(/^did:vh:[1-9A-HJ-NP-Za-km-z]{46}$/);
  expect(genesis.parameters.scid).toBe(genesis.state.id.slice("did:vh:".length));
  expect(genesis.parameters.method).toBe("did:vh:1.0");
  expect(genesis.state.verificationMethod[0].id).toBe("#pass-1");
  expect(genesis.state.authentication).toEqual(["#pass-1"]);
  expect(genesis.state.service).toEqual([]);
  expect(locationsOf(genesis.state.id, genesis.state)).toEqual([]);
  await resolveVhLog(genesis.state.id, [genesis]);
});

// Wallet discovery (atproto-style): a relying party resolves the user's own DID document to find where the
// identity's authorization screen is. Supplying `api` publishes it as a "#wallet" service.
test("a genesis publishes a SelfIssuedOPAuthorizationEndpoint service entry when api is supplied, before any caller-supplied entries", async () => {
  const identity = await createIdentityMaterial();
  const bare = await createGenesisEntry({ root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare });
  expect(bare.state.service).toEqual([]);
  const genesis = await createGenesisEntry({
    root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare, api: "https://api.did.md",
    service: [{ id: "#oauth-redirect", type: "OAuthRedirectTarget", serviceEndpoint: "https://t.biset.md/wallet/callback" }],
  });
  expect(genesis.state.service).toEqual([
    { id: "#wallet", type: "SelfIssuedOPAuthorizationEndpoint", serviceEndpoint: "https://api.did.md" },
    { id: "#oauth-redirect", type: "OAuthRedirectTarget", serviceEndpoint: "https://t.biset.md/wallet/callback" },
  ]);
});

test("a genesis born at a place already names it", async () => {
  const identity = await createIdentityMaterial();
  const genesis = await createGenesisEntry({ root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare, src: "https://alice.did.md" });
  expect(genesis.state.alsoKnownAs).toContain("did:web:alice.did.md");
  expect(locationsOf(genesis.state.id, genesis.state).map(location => location.src)).toEqual(["https://alice.did.md"]);
  await resolveVhLog(genesis.state.id, [genesis]);
});

test("the Master-derived Spare creates a valid pre-rotated update and commits its successor", async () => {
  const identity = await createIdentityMaterial();
  const genesis = await createGenesisEntry({ root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare });
  const result = await prepareUpdateEntry({ entries: [genesis], state: genesis.state, masterSeed: identity.masterSeed, currentSpareIndex: 0 });
  const spare1 = await spareFromMasterSeed(identity.masterSeed, 1);

  expect(result.entry.parameters.updateKeys).toEqual([identity.nextSpare.multikey]);
  expect(result.entry.parameters.nextKeyHashes).toEqual([keyHash(spare1.multikey)]);
  expect(result.nextSpare.multikey).toBe(spare1.multikey);
  expect(result.nextSpareIndex).toBe(1);

  const { proof, ...unsigned } = result.entry;
  expect(await verifyProofSignature(unsigned, proof[0]!, ed25519.getPublicKey(identity.nextSpare.privateKey))).toBe(true);
  await resolveVhLog(genesis.state.id, [genesis, result.entry]);
  expect(currentVhParameters([genesis, result.entry]).nextKeyHashes).toEqual([keyHash(spare1.multikey)]);
});

test("a location entry keeps the history and the DID, and names the new place instead of the old one", async () => {
  const identity = await createIdentityMaterial();
  const genesis = await createGenesisEntry({
    root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare, src: "https://old.example",
    service: [{ id: "#files", type: "relativeRef", serviceEndpoint: "https://old.example/" }],
  });
  const did = genesis.state.id;
  const moved = await prepareLocationEntry({ entries: [genesis], src: "https://alice.did.md", previousSrc: "https://old.example", masterSeed: identity.masterSeed, currentSpareIndex: 0 });

  expect(genesis.state.id).toBe(did);
  expect(moved.state.id).toBe(did);
  expect(locationsOf(did, moved.state).map(location => location.src)).toEqual(["https://alice.did.md"]);
  expect(moved.state.alsoKnownAs).not.toContain("did:web:old.example");
  expect(moved.state.service[0].serviceEndpoint).toBe("https://old.example/"); // other services stay under the controller
  expect(moved.entry.parameters.updateKeys).toEqual([identity.nextSpare.multikey]);
  expect(moved.nextSpareIndex).toBe(1);
  await resolveVhLog(did, [genesis, moved.entry]);
});

test("a location entry is refused when the Passphrase does not match the log's commitment", async () => {
  const identity = await createIdentityMaterial();
  const other = await createIdentityMaterial();
  const genesis = await createGenesisEntry({ root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare });
  await expect(prepareLocationEntry({ entries: [genesis], src: "https://alice.did.md", masterSeed: other.masterSeed, currentSpareIndex: 0 })).rejects.toThrow(/commitment/);
});

test("Wallet issues an audience-bound generic key credential signed by both Root and current Sign", async () => {
  const identity = await createIdentityMaterial();
  const did = `did:vh:${"Q".repeat(46)}`;
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
  const signingBytes = new TextEncoder().encode(jcs({
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
  await expect(createKeyAuthorizationCredentialWire({
    issuer: `did:web:alice.did.md`, audience: "client_test", subject: "urn:uuid:11111111-1111-4111-8111-111111111111", generation: "1-QmNf4Y7DyYWTZcrMdQMwftYe5JmcKXfPrxpqwriHa3A7w5",
    publicKey: { type: "Multikey", publicKeyMultibase: identity.sign.multikey }, purposes: ["signing"], issuedAt: "2026-09-09T00:00:00.000Z", expiresAt: "2026-10-09T00:00:00.000Z",
    rootPrivateKey: identity.root.privateKey, signPrivateKey: identity.sign.privateKey,
  })).rejects.toThrow("invalid");
});

// PLAN6: a relying party (biset/oidc-bridge) authenticates its Authorization Request with a JAR (RFC 9101) signed by its
// own did:vh key, rather than a DCR-issued client_id/secret. verifyRequestObjectJws is the wallet-UI-side verifier
// (browser-safe -- see packages/did-verify for the equivalent used by oidc-bridge's Node backend). The RP's log comes
// from the `src` its kid carries, or from the wallet's own watchers.
function base64url(bytes: Uint8Array): string {
  let binary = ""; for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
// A real, signed RP log whose #key-1 is `privateKey`, published at https://t.biset.md.
async function rpLog(privateKey: Uint8Array, services: unknown[] = []) {
  const key = keyFromPrivateKey(privateKey);
  return createVhLog({
    signer: key, updateKeys: [key.multikey],
    document: did => withLocation({
      "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"], id: did,
      verificationMethod: [{ id: "#key-1", type: "Multikey", controller: did, publicKeyMultibase: key.multikey }], authentication: ["#key-1"], service: services,
    }, did, "https://t.biset.md"),
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

function serving(log: VhLogEntry[], seen: string[] = []) {
  globalThis.fetch = (async (url: string | URL) => { seen.push(String(url)); return new Response(serializeVhLog(log), { status: 200 }); }) as typeof fetch;
  return seen;
}

test("verifyRequestObjectJws resolves the RP's did:vh key from the src its kid names, and returns its service array", async () => {
  const privateKey = ed25519.utils.randomSecretKey();
  const services = [{ id: "#oauth-redirect", type: "OAuthRedirectTarget", serviceEndpoint: "https://t.biset.md/wallet/callback" }];
  const created = await rpLog(privateKey, services);
  const jwt = signedRequestObject(privateKey, `${created.did}?src=${encodeURIComponent("https://t.biset.md")}#key-1`, { hello: "world" });
  const seen = serving(created.log);
  const result = await verifyRequestObjectJws(jwt);
  expect(result.rpDid).toBe(created.did);
  expect(result.payload).toEqual({ hello: "world" });
  expect(seen[0]).toContain("https://t.biset.md/.well-known/did.jsonl");
  for (const service of services) expect(result.service).toContainEqual(service);
  expect(locationsOf(result.rpDid, result.document)[0]?.src).toBe("https://t.biset.md");
});

test("without a src in the kid, the wallet's own watchers are asked", async () => {
  const privateKey = ed25519.utils.randomSecretKey();
  const created = await rpLog(privateKey);
  const jwt = signedRequestObject(privateKey, `${created.did}#key-1`, {});
  const seen = serving(created.log);
  await expect(verifyRequestObjectJws(jwt)).rejects.toThrow(/watcher/);
  expect(seen).toEqual([]);
  const result = await verifyRequestObjectJws(jwt, { watchers: ["https://did.md"] });
  expect(result.rpDid).toBe(created.did);
  expect(seen[0]).toContain(`https://did.md/log?scid=${created.did.slice("did:vh:".length)}`);
});

test("verifyRequestObjectJws rejects a tampered payload", async () => {
  const privateKey = ed25519.utils.randomSecretKey();
  const created = await rpLog(privateKey);
  const jwt = signedRequestObject(privateKey, `${created.did}?src=https://t.biset.md#key-1`, { state: "original" });
  const [header, , signature] = jwt.split(".");
  const tampered = `${header}.${base64url(new TextEncoder().encode(JSON.stringify({ state: "tampered" })))}.${signature}`;
  serving(created.log);
  await expect(verifyRequestObjectJws(tampered)).rejects.toThrow("signature is invalid");
});

test("verifyRequestObjectJws rejects an RP log that does not validate (forged document key) and a log of another DID", async () => {
  const privateKey = ed25519.utils.randomSecretKey();
  const created = await rpLog(privateKey);
  const forged = JSON.parse(JSON.stringify(created.log));
  forged[0].state.verificationMethod[0].publicKeyMultibase = keyFromPrivateKey(ed25519.utils.randomSecretKey()).multikey;
  const jwt = signedRequestObject(privateKey, `${created.did}?src=https://t.biset.md#key-1`, {});
  serving(forged);
  await expect(verifyRequestObjectJws(jwt)).rejects.toThrow();
  // a valid log, but not the SCID the request names
  const other = await rpLog(ed25519.utils.randomSecretKey());
  serving(other.log);
  await expect(verifyRequestObjectJws(jwt)).rejects.toThrow();
});

test("a src that is an IP address or not https is refused before anything is fetched (SSRF)", async () => {
  const privateKey = ed25519.utils.randomSecretKey();
  const created = await rpLog(privateKey);
  globalThis.fetch = (async () => { throw new Error("must not fetch"); }) as typeof fetch;
  for (const src of ["https://127.0.0.1", "http://t.biset.md", "https://169.254.169.254", "https://user:pw@t.biset.md"]) {
    const jwt = signedRequestObject(privateKey, `${created.did}?src=${encodeURIComponent(src)}#key-1`, {});
    await expect(verifyRequestObjectJws(jwt)).rejects.not.toThrow("must not fetch");
  }
  await expect(resolveRpDocument(`did:web:t.biset.md`)).rejects.toThrow(/did:vh/);
});
