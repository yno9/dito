// Verifying a did:vh signer (packages/did-verify): the log comes from the verifier's watchers, not from the token.
import { afterEach, expect, test } from "vitest";
import { InMemoryVersionMemory, StaleLogError } from "../packages/webvh/src/index.ts";
import { deactivateVhLog } from "../packages/vh/src/index.ts";
import { clearDidDocumentCache, resolveDidVhDocument, stableSubject, verifyIdTokenSignature, verifyViaDidVh } from "../packages/did-verify/index.ts";
import { createSelfIssuedIdToken } from "../packages/wallet/src/did-webvh.ts";
import { VhIdentity } from "../packages/wallet/src/vh-identity.ts";
import { DitoClient } from "../server/oauth/src/dito-client.ts";
import { freshHost, resetHost, viaHost } from "./helpers/vh-host.ts";

afterEach(() => { resetHost(); clearDidDocumentCache(); });

const claims = (did: string) => ({ iss: did, sub: did, aud: "https://rp.example", iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 300 });

/** A hosted did:vh identity, its Root key (what signs an id_token), and a verifier's sources. */
async function hosted(name = "alice") {
  freshHost();
  const { identity } = await VhIdentity.create({ fetch: viaHost });
  await identity.connect({ username: name });
  const root = (identity as unknown as { _root: { privateKey: Uint8Array } })._root;
  return { identity, root, sources: () => ({ watchers: ["https://did.md"], fetch: viaHost, memory: new InMemoryVersionMemory() }) };
}

test("an id_token signed by a did:vh identity verifies against the log its watcher serves", async () => {
  const { identity, root, sources } = await hosted();
  const token = createSelfIssuedIdToken(claims(identity.did), { privateKey: root.privateKey, did: identity.did });
  const signer = await verifyIdTokenSignature(token, "did.md", sources());
  expect(signer).toMatchObject({ sub: identity.did, method: "did-vh" });
  expect(stableSubject(signer.sub)).toBe(identity.did);
});

test("a did:vh signer cannot be verified without watchers: the token does not get to say where its log is", async () => {
  const { identity, root } = await hosted();
  const token = createSelfIssuedIdToken(claims(identity.did), { privateKey: root.privateKey, did: identity.did });
  await expect(verifyIdTokenSignature(token, "did.md")).rejects.toThrow(/needs a verifier with watchers/);
  await expect(verifyIdTokenSignature(token, "did.md", { watchers: ["https://nobody.example"], fetch: (async () => new Response("", { status: 404 })) as typeof fetch })).rejects.toThrow(/not found at any accepted watcher/);
});

test("a token signed by another key is refused, and so is a kid that is not an authentication method", async () => {
  const { identity, sources } = await hosted();
  const stranger = (await VhIdentity.create()).identity as unknown as { _root: { privateKey: Uint8Array } };
  const forged = createSelfIssuedIdToken(claims(identity.did), { privateKey: stranger._root.privateKey, did: identity.did });
  await expect(verifyIdTokenSignature(forged, "did.md", sources())).rejects.toThrow(/signature is invalid/);
  const { root } = await hosted("bob");
  const wrongKid = createSelfIssuedIdToken(claims(identity.did), { privateKey: root.privateKey, did: identity.did }).split(".");
  const header = JSON.parse(Buffer.from(wrongKid[0]!, "base64url").toString());
  header.kid = `${identity.did}#nope`;
  wrongKid[0] = Buffer.from(JSON.stringify(header)).toString("base64url");
  await expect(verifyIdTokenSignature(wrongKid.join("."), "did.md", sources())).rejects.toThrow();
});

test("the issuer domain is checked through the did:web DID the document names", async () => {
  const { identity, root, sources } = await hosted();
  const token = createSelfIssuedIdToken(claims(identity.did), { privateKey: root.privateKey, did: identity.did });
  await verifyViaDidVh(token, `${identity.did}#pass-1`, sources(), "did.md");
  await expect(verifyViaDidVh(token, `${identity.did}#pass-1`, sources(), "example.com")).rejects.toThrow(/not an accepted issuer domain/);
  // No restriction asked for: any log the watcher serves.
  await verifyViaDidVh(token, `${identity.did}#pass-1`, sources());
});

test("a log older than one already accepted is refused, so a watcher cannot roll a key rotation back", async () => {
  const { identity, sources: make } = await hosted();
  const sources = make();
  await resolveDidVhDocument(identity.did, sources);
  const older = identity.logText();
  await identity.rotate();
  clearDidDocumentCache();
  const current = await resolveDidVhDocument(identity.did, sources);
  expect(current.id).toBe(identity.did);
  // A watcher (or something in front of it) now serves the log as it was before the rotation: it verifies on its own.
  clearDidDocumentCache();
  const rolledBack = { ...sources, fetch: (async (input: RequestInfo | URL) => String(input).includes("/log?") ? new Response(older) : viaHost(input)) as typeof fetch };
  await expect(resolveDidVhDocument(identity.did, rolledBack)).rejects.toThrow(StaleLogError);
  // Without that memory the same log is accepted: that is what the memory is for.
  await expect(resolveDidVhDocument(identity.did, { ...rolledBack, memory: new InMemoryVersionMemory() })).resolves.toMatchObject({ id: identity.did });
});

test("a deactivated did:vh DID no longer signs anyone in", async () => {
  const { identity, root, sources } = await hosted("carol");
  const token = createSelfIssuedIdToken(claims(identity.did), { privateKey: root.privateKey, did: identity.did });
  const spare = await (await import("../packages/wallet/src/did-webvh.ts")).spareFromMasterSeed((identity as any).masterSeed, (identity as any)._spareIndex);
  const done = await deactivateVhLog({ log: [...identity.entries], signer: spare, now: Date.now() + 5000 });
  const posted = await viaHost("https://carol.did.md/.well-known/did.jsonl", { method: "POST", body: `${JSON.stringify(done.log.at(-1))}\n` });
  expect(posted.status).toBe(204);
  await expect(verifyIdTokenSignature(token, "did.md", sources())).rejects.toThrow(/deactivated/);
});

test("stableSubject: a did:vh DID and a JWK thumbprint are already stable; a did:webvh DID loses its location", () => {
  const scid = "Q".repeat(46);
  expect(stableSubject(`did:vh:${scid}`)).toBe(`did:vh:${scid}`);
  expect(stableSubject(`did:webvh:${scid}:alice.did.md`)).toBe(`did:webvh:${scid}`);
  expect(stableSubject("5Kz1u3Vq0fMw9y2m4a7mQ0aVJ3d1x8Z6bq0wq2c3XyA")).toBe("5Kz1u3Vq0fMw9y2m4a7mQ0aVJ3d1x8Z6bq0wq2c3XyA");
  expect(stableSubject(`did:vh:${scid}#k`)).toBe(`did:vh:${scid}#k`);
});

test("the OIDC bridge client gets a did:vh wallet identity's log from the wallet's identity host", () => {
  const client = new DitoClient("https://dito.did.md", "https://bridge.example/callback", "/nonexistent/registration.json", undefined, "did.md");
  expect(client.vhSources.watchers).toEqual(["https://did.md"]);
});
