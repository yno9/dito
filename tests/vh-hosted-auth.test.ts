// The host's own identity check (hostedAuthenticationKey / verifySelfIssuedIdToken) for a did:vh issuer: the log is fetched by SCID from
// this identity domain's watcher endpoint, here a real local HTTP server standing in for it (IDENTITY_FETCH_BASE_URL).
import { fetchBasePort } from "./helpers/fetch-base.ts";
import { afterAll, beforeAll, expect, test } from "vitest";
import { serve, type Served } from "../server/serve.ts";
import { freshHost, viaHost } from "./helpers/vh-host.ts";
import * as host from "../server/host/identity-host.ts";
import { VhIdentity } from "../packages/wallet/src/vh-identity.ts";
import { createSelfIssuedIdToken } from "../packages/wallet/src/did-webvh.ts";

let served: Served;

beforeAll(() => {
  freshHost();
  served = serve({ port: fetchBasePort, hostname: "127.0.0.1", fetch: async request => (await host.identityFetch(request, new URL(request.url))) ?? new Response("not found\n", { status: 404 }) });
});
afterAll(() => { served?.stop(true); });

async function published() {
  const { identity } = await VhIdentity.create({ fetch: viaHost });
  await identity.connect({ username: "alice" });
  return identity;
}
const claims = (did: string, aud = "https://rp.example") => ({ iss: did, sub: did, aud, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 300 });

test("the host resolves a did:vh issuer's authentication key by SCID, and verifies a self-issued id_token with it", async () => {
  const identity = await published();
  const root = (identity as unknown as { _root: { privateKey: Uint8Array } })._root;
  const authority = await host.hostedAuthenticationKey(identity.did, `${identity.did}#pass-1`);
  expect(authority).toMatchObject({ did: identity.did, verificationMethod: `${identity.did}#pass-1`, keyType: "Ed25519" });
  const token = createSelfIssuedIdToken(claims(identity.did), { privateKey: root.privateKey, did: identity.did });
  const verified = await host.verifySelfIssuedIdToken(token, identity.did, "https://rp.example", 5 * 60_000);
  expect(verified).toBeTruthy();
  // Another key signing for that DID is refused.
  const stranger = (await VhIdentity.create()).identity as unknown as { _root: { privateKey: Uint8Array } };
  const forged = createSelfIssuedIdToken(claims(identity.did), { privateKey: stranger._root.privateKey, did: identity.did });
  await expect(host.verifySelfIssuedIdToken(forged, identity.did, "https://rp.example", 5 * 60_000)).rejects.toThrow();
});

test("an unknown or malformed did:vh issuer is refused", async () => {
  await expect(host.hostedAuthenticationKey(`did:vh:${"1".repeat(46)}`)).rejects.toThrow(/was not found/);
  await expect(host.hostedAuthenticationKey("did:vh:nope")).rejects.toThrow(/not a valid did:vh/);
});
