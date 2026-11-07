// The browser wallet's pure modules (no DOM): identity container reading and
// OAuth authorization_details validation.
import { expect, test } from "vitest";
import { createIdentityMaterial } from "../packages/wallet/src/keys.ts";
import { createGenesisEntry } from "../packages/wallet/src/vh-ops.ts";
import { sealIdentityContainer } from "../packages/wallet/src/identity-container.ts";
import { decryptIdentityContainer } from "../packages/wallet/src/wallet-backup.ts";
import { checkedIdentityContainer, containerPath, parseLog, scidFromDid } from "../client/identity-container.ts";
import {
  DERIVED_SECRET_DETAIL, DID_DOCUMENT_EDIT_DETAIL, KEY_AUTHORIZATION_DETAIL,
  derivedSecretDetails, didDocumentEditDetail, keyAuthorizationDetail, oauthAuthorizationDetails,
} from "../client/authorization-details.ts";

test("a v3 container sealed by the wallet package reads back in the browser's checker", async () => {
  const material = await createIdentityMaterial();
  const entry = await createGenesisEntry({ root: material.root, sign: material.sign, nextSpare: material.nextSpare });
  const did = entry.state.id;
  const didJsonl = `${JSON.stringify(entry)}\n`;
  const jwe = await sealIdentityContainer({ scid: scidFromDid(did), did, rootKey: material.root.multikey, generation: entry.versionId, didJsonl, masterSeed: material.masterSeed });
  const parsed = checkedIdentityContainer(await decryptIdentityContainer(jwe, material.masterSeed));
  expect(parsed.version).toBe(3);
  expect(parsed.identities).toHaveLength(1);
  const [identity] = parsed.identities as any[];
  expect(identity.did).toBe(did);
  expect(identity.username).toBeUndefined();
  expect(identity.didJsonl).toBe(didJsonl);
  expect([...identity.masterSeed]).toEqual([...material.masterSeed]);
  expect(containerPath(did, "did.jsonl")).toBe(`identities/${scidFromDid(did)}/did.jsonl`);
});

test("container checks reject what they do not support", () => {
  expect(() => checkedIdentityContainer({ format: "did.md/identity-container", version: 4 })).toThrow("not a supported");
  expect(() => checkedIdentityContainer(null)).toThrow("not a supported");
  expect(() => parseLog('{"truncated":true}')).toThrow("Public log was not found.");
  expect(() => scidFromDid("did:web:example.com")).toThrow("SCID");
});

test("authorization_details: parsed, typed, and absent when not requested", () => {
  expect(oauthAuthorizationDetails(null)).toEqual([]);
  expect(() => oauthAuthorizationDetails("[]")).toThrow("invalid");
  expect(() => oauthAuthorizationDetails('[{"type":"1bad"}]')).toThrow("invalid");
  const details = oauthAuthorizationDetails(JSON.stringify([{ type: "urn:other:v1" }]));
  expect(didDocumentEditDetail(details, "")).toBeUndefined();
  expect(keyAuthorizationDetail(details)).toBeUndefined();
  expect(derivedSecretDetails(details)).toEqual([]);
});

test("a document edit forces the wallet's own DID as controller and spares the Root key", () => {
  const did = `did:vh:${"Q".repeat(46)}`;
  const method = { id: "#k1", type: "Multikey", controller: "did:example:rp", publicKeyMultibase: "z6Mk" };
  const edit = didDocumentEditDetail([{ type: DID_DOCUMENT_EDIT_DETAIL, services: [], verificationMethods: [method], remove: [] }], did);
  expect(edit?.verificationMethods[0].controller).toBe(did);
  expect(() => didDocumentEditDetail([{ type: DID_DOCUMENT_EDIT_DETAIL, services: [], verificationMethods: [], remove: ["#pass-1"] }], did)).toThrow();
  expect(() => didDocumentEditDetail([{ type: DID_DOCUMENT_EDIT_DETAIL, services: [], verificationMethods: [], remove: [], extra: 1 }], did)).toThrow("unexpected fields");
});

test("key authorization and derived secret requests are shape-checked", () => {
  const key = { type: KEY_AUTHORIZATION_DETAIL, subject: "urn:uuid:00000000-0000-4000-8000-000000000000", publicKey: { type: "Multikey", publicKeyMultibase: "z6Mk" }, purposes: ["sign"] };
  expect(keyAuthorizationDetail([key])).toEqual(key);
  expect(() => keyAuthorizationDetail([key, key])).toThrow("duplicated");
  const secret = { type: DERIVED_SECRET_DETAIL, purpose: "storage", context: "a" };
  expect(derivedSecretDetails([secret, { ...secret, context: "b" }])).toHaveLength(2);
  expect(() => derivedSecretDetails([secret, secret])).toThrow("duplicated");
});
