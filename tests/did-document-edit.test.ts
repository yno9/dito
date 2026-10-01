import { expect, test } from "bun:test";
import { sameDidDocumentReference, withDidDocumentEdit } from "../packages/wallet/src/did-document-edit.ts";

const did = "did:webvh:Qm123:alice.did.md";
const state = {
  id: did,
  verificationMethod: [{ id: `${did}#old`, type: "Multikey" }],
  keyAgreement: [`${did}#old`],
  service: [{ id: "#svc", type: "X", serviceEndpoint: "https://a.example" }],
};

test("relative and absolute references compare equal", () => {
  expect(sameDidDocumentReference(did, "#a", `${did}#a`)).toBe(true);
  expect(sameDidDocumentReference(did, "#a", "#b")).toBe(false);
});

test("adds, replaces and removes by id without mutating the input", () => {
  const before = JSON.stringify(state);
  const next = withDidDocumentEdit(state, {
    remove: ["#old"],
    verificationMethods: [{ id: `${did}#new` }],
    services: [{ id: `${did}#svc`, type: "X", serviceEndpoint: "https://b.example" }, { id: "#extra" }],
  });
  expect(JSON.stringify(state)).toBe(before);
  expect(next.verificationMethod).toEqual([{ id: `${did}#new` }]);
  expect(next.keyAgreement).toEqual([`${did}#new`]);
  expect(next.service).toEqual([{ id: `${did}#svc`, type: "X", serviceEndpoint: "https://b.example" }, { id: "#extra" }]);
});

test("an edit that changes nothing yields an identical document", () => {
  const next = withDidDocumentEdit({ ...state, keyAgreement: undefined }, { remove: [], verificationMethods: [], services: [] });
  expect(next).toEqual({ ...state, keyAgreement: undefined });
});
