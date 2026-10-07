// On a did.md identity only the Root key (#pass-1) signs the user in; other
// authentication keys there were added for relying parties (a messaging app's
// DID Rotation signing key) and must not act as the user everywhere. A
// document without #pass-1 is another wallet's, whose key names are not
// assumed (PLAN1): any authentication key signs in.
import { expect, test } from "bun:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { maySignIn, multikeyFromPublicKey } from "../packages/webvh/src/index.ts";
import { authenticationKeyFromState } from "../server/host/identity-host.ts";

const did = "did:webvh:QmScid:alice.did.md";
const key = () => multikeyFromPublicKey(ed25519.getPublicKey(ed25519.utils.randomSecretKey()));
const dito = {
  id: did,
  verificationMethod: [{ id: "#pass-1", type: "Multikey", controller: did, publicKeyMultibase: key() }, { id: "#didcomm-rotation", type: "Multikey", controller: did, publicKeyMultibase: key() }],
  authentication: ["#didcomm-rotation", "#pass-1"],
};
const otherWallet = {
  id: did,
  verificationMethod: [{ id: "#key-7", type: "Multikey", controller: did, publicKeyMultibase: key() }],
  authentication: [`${did}#key-7`],
};

test("on a did.md identity only #pass-1 may sign in, whatever else authenticates and in whatever order", () => {
  expect(maySignIn(dito, did, `${did}#pass-1`)).toBe(true);
  expect(maySignIn(dito, did, `${did}#didcomm-rotation`)).toBe(false);
  expect(maySignIn(dito, did, `${did}#not-there`)).toBe(false);
});

test("another wallet's identity signs in with any of its authentication keys", () => {
  expect(maySignIn(otherWallet, did, `${did}#key-7`)).toBe(true);
});

test("the identity layer resolves only a key that may sign in", () => {
  expect(authenticationKeyFromState(did, dito as never, "#pass-1").verificationMethod).toBe(`${did}#pass-1`);
  expect(() => authenticationKeyFromState(did, dito as never, `${did}#didcomm-rotation`)).toThrow("no matching authentication method");
  // Unnamed, the Root is the one: the other key does not make it ambiguous.
  expect(authenticationKeyFromState(did, dito as never).verificationMethod).toBe(`${did}#pass-1`);
  expect(authenticationKeyFromState(did, otherWallet as never, "#key-7").verificationMethod).toBe(`${did}#key-7`);
});
