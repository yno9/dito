import { expect, test } from "bun:test";
import { endpointIdentity, mergeServiceEndpoints, sameDidDocumentReference, withDidDocumentEdit } from "../packages/wallet/src/did-document-edit.ts";

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

// A service with several endpoints (DID Core: a set of strings and/or maps) is shared by
// everyone who publishes to it; the edit addresses its endpoints one by one.
const messaging = (serviceEndpoint: unknown) => ({ id: "#chat", type: "Messaging", serviceEndpoint });
const a = { uri: "https://a.example", accept: ["v2"] };
const b = { uri: "http://b.onion/", accept: ["v2"] };
const none = { remove: [], verificationMethods: [] };
const withService = (service: unknown) => ({ ...state, service: [service] });

test("endpoint identity: a string is itself, a map is its uri, anything else has none", () => {
  expect(endpointIdentity("https://a.example")).toBe("https://a.example");
  expect(endpointIdentity(a)).toBe("https://a.example");
  expect(endpointIdentity({ accept: ["v2"] })).toBeUndefined();
  expect(endpointIdentity(["x"])).toBeUndefined();
});

test("merge adds an endpoint to the existing service and keeps the others", () => {
  const next = withDidDocumentEdit(withService(messaging(a)), { ...none, services: [{ ...messaging(b), endpointMode: "merge" }] });
  expect(next.service).toEqual([messaging([a, b])]);
});

test("merge updates the endpoint with the same uri in place and never reorders", () => {
  const before = withService(messaging([a, b]));
  const next = withDidDocumentEdit(before, { ...none, services: [{ ...messaging({ ...a, accept: ["v2", "v3"] }), endpointMode: "merge" }] });
  expect(next.service).toEqual([messaging([{ ...a, accept: ["v2", "v3"] }, b])]);
});

test("merging an endpoint that is already there changes nothing", () => {
  const before = withService(messaging(a));
  expect(withDidDocumentEdit(before, { ...none, services: [{ ...messaging(a), endpointMode: "merge" }] })).toEqual(before);
});

test("merge into a service that is not there creates it; a single endpoint stays a single map", () => {
  const next = withDidDocumentEdit(state, { ...none, services: [{ ...messaging(a), endpointMode: "merge" }] });
  expect(next.service.at(-1)).toEqual(messaging(a));
});

test("merge of a service whose type differs replaces it instead", () => {
  const next = withDidDocumentEdit(withService({ id: "#chat", type: "Other", serviceEndpoint: a }), { ...none, services: [{ ...messaging(b), endpointMode: "merge" }] });
  expect(next.service).toEqual([messaging(b)]);
});

test("without endpointMode (or with replace) a service is still replaced as a whole", () => {
  const before = withService(messaging([a, b]));
  expect(withDidDocumentEdit(before, { ...none, services: [messaging(a)] }).service).toEqual([messaging(a)]);
  expect(withDidDocumentEdit(before, { ...none, services: [{ ...messaging(a), endpointMode: "replace" }] }).service).toEqual([messaging(a)]);
});

test("string endpoints merge by their value", () => {
  const next = withDidDocumentEdit(withService(messaging("https://a.example")), { ...none, services: [{ ...messaging(["https://a.example", "https://c.example"]), endpointMode: "merge" }] });
  expect(next.service).toEqual([messaging(["https://a.example", "https://c.example"])]);
  expect(mergeServiceEndpoints(undefined, a)).toEqual(a);
});

test("removeEndpoints removes the endpoints matching every given property, collapsing a set of one", () => {
  const onion = { ...b, routingKeys: ["did:ex:m#k"] };
  const next = withDidDocumentEdit(withService(messaging([{ ...a, routingKeys: ["did:ex:m#k"] }, onion])), { ...none, services: [], removeEndpoints: [{ serviceId: "#chat", match: { uri: "http://b.onion/" } }] });
  expect(next.service).toEqual([messaging({ ...a, routingKeys: ["did:ex:m#k"] })]);
});

test("removeEndpoints can match on any property, so one call removes every endpoint of a retired target", () => {
  const keys = ["did:ex:old#k"];
  const next = withDidDocumentEdit(withService(messaging([{ ...a, routingKeys: keys }, { ...b, routingKeys: keys }])), { ...none, services: [], removeEndpoints: [{ serviceId: "#chat", match: { routingKeys: keys } }] });
  expect(next.service).toEqual([]);
});

test("removeEndpoints runs before the services of the same edit, and a string endpoint matches on uri", () => {
  const next = withDidDocumentEdit(withService(messaging("https://old.example")), {
    ...none, removeEndpoints: [{ serviceId: "#chat", match: { uri: "https://old.example" } }], services: [{ ...messaging(a), endpointMode: "merge" }],
  });
  expect(next.service).toEqual([messaging(a)]);
});

test("removeEndpoints with no match, or for a service that is not there, changes nothing", () => {
  const before = withService(messaging([a, b]));
  expect(withDidDocumentEdit(before, { ...none, services: [], removeEndpoints: [{ serviceId: "#chat", match: { uri: "https://nope" } }, { serviceId: "#absent", match: { uri: "x" } }] })).toEqual(before);
});

import { assertEndpointRemovals, assertServiceEndpointMode } from "../packages/wallet/src/did-document-edit.ts";

test("endpoint mode: absent, replace and merge are accepted; anything else, or merging an endpoint without a uri, is not", () => {
  expect(() => assertServiceEndpointMode({ serviceEndpoint: a })).not.toThrow();
  expect(() => assertServiceEndpointMode({ endpointMode: "replace", serviceEndpoint: { accept: ["v2"] } })).not.toThrow();
  expect(() => assertServiceEndpointMode({ endpointMode: "merge", serviceEndpoint: [a, "https://c.example"] })).not.toThrow();
  expect(() => assertServiceEndpointMode({ endpointMode: "union", serviceEndpoint: a })).toThrow("endpoint mode");
  expect(() => assertServiceEndpointMode({ endpointMode: "merge", serviceEndpoint: [a, { accept: ["v2"] }] })).toThrow("no uri");
});

test("endpoint removals: a service id and a non-empty match are required, and nothing else is allowed", () => {
  const validId = (id: unknown) => typeof id === "string" && id.startsWith("#");
  expect(() => assertEndpointRemovals([{ serviceId: "#chat", match: { uri: "x" } }], validId)).not.toThrow();
  expect(() => assertEndpointRemovals([], validId)).not.toThrow();
  for (const bad of [
    "nope", [{ serviceId: "#chat", match: {} }], [{ serviceId: "chat", match: { uri: "x" } }], [{ serviceId: "#chat" }],
    [{ serviceId: "#chat", match: { uri: "x" }, extra: 1 }], [{ serviceId: "#chat", match: ["x"] }], [null],
    Array.from({ length: 65 }, () => ({ serviceId: "#chat", match: { uri: "x" } })),
    [{ serviceId: "#chat", match: Object.fromEntries(Array.from({ length: 9 }, (_, i) => [`k${i}`, i])) }],
  ]) expect(() => assertEndpointRemovals(bad, validId)).toThrow("removal");
});
