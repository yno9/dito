import { expect, test } from "vitest";
import {
  Ed25519Signer, createLog, keyFromPrivateKey, nextKeyHash, parseLog, resolveLog, serializeLog, updateLog,
} from "../packages/webvh/src/index.ts";
import { validateLogAt } from "../packages/wallet/src/webvh-core.ts";

const key = () => keyFromPrivateKey(crypto.getRandomValues(new Uint8Array(32)));

async function twoKeyLog() {
  const [k0, k1, k2] = [key(), key(), key()];
  const s0 = new Ed25519Signer(k0);
  const created = await createLog({
    domain: "example.com", signer: s0, updateKeys: [k0.multikey], nextKeyHashes: [await nextKeyHash(k1.multikey)],
    verificationMethods: [{ id: "#k", type: "Multikey", publicKeyMultibase: k0.multikey }], authentication: ["#k"],
  });
  return { created, k0, k1, k2 };
}

test("createLog + updateLog produce a log both didwebvh-ts and the did.md validator accept", async () => {
  const { created, k1, k2 } = await twoKeyLog();
  const s1 = new Ed25519Signer(k1);
  const updated = await updateLog({ log: created.log, signer: s1, updateKeys: [k1.multikey], nextKeyHashes: [await nextKeyHash(k2.multikey)] });
  expect(updated.log).toHaveLength(2);
  await resolveLog(updated.log);
  await validateLogAt(updated.log as never, [], "https://example.com/.well-known/did.jsonl");
});

test("a pre-rotated update can move the DID to a new domain, keeping the SCID", async () => {
  const { created, k1, k2 } = await twoKeyLog();
  const s1 = new Ed25519Signer(k1);
  const moved = await updateLog({ log: created.log, signer: s1, updateKeys: [k1.multikey], nextKeyHashes: [await nextKeyHash(k2.multikey)], domain: "alice.did.md" });
  expect(moved.did.endsWith(":alice.did.md")).toBe(true);
  expect(moved.did.split(":")[2]).toBe(created.did.split(":")[2]);
  await validateLogAt(moved.log as never, [], "https://alice.did.md/.well-known/did.jsonl");
});

test("an update signed by a key that was not pre-committed is rejected", async () => {
  const { created, k0, k2 } = await twoKeyLog();
  const wrong = new Ed25519Signer(k2);
  await expect(updateLog({ log: created.log, signer: wrong, updateKeys: [k2.multikey], nextKeyHashes: [await nextKeyHash(key().multikey)] })).rejects.toThrow();
  expect(k0.multikey).toBeTruthy();
});

test("parseLog/serializeLog round-trip and reject a tampered entry", async () => {
  const { created, k1, k2 } = await twoKeyLog();
  const updated = await updateLog({ log: created.log, signer: new Ed25519Signer(k1), updateKeys: [k1.multikey], nextKeyHashes: [await nextKeyHash(k2.multikey)] });
  const text = serializeLog(updated.log);
  expect(parseLog(text)).toEqual(updated.log);
  expect(() => parseLog(text.trimEnd())).toThrow(/newline/);
  const tampered = parseLog(text);
  tampered[1].state = { ...tampered[1].state, service: [{ id: "#x", type: "X", serviceEndpoint: "https://evil.example" }] };
  await expect(resolveLog(tampered)).rejects.toThrow();
});

test("an entry with an empty proof array is rejected (didwebvh-ts alone accepts it)", async () => {
  const { created, k1, k2 } = await twoKeyLog();
  const updated = await updateLog({ log: created.log, signer: new Ed25519Signer(k1), updateKeys: [k1.multikey], nextKeyHashes: [await nextKeyHash(k2.multikey)] });
  await expect(resolveLog([{ ...created.log[0]!, proof: [] }])).rejects.toThrow(/proof/i);
  await expect(resolveLog([created.log[0]!, { ...updated.log[1]!, proof: [] }])).rejects.toThrow(/proof/i);
  await expect(validateLogAt([{ ...created.log[0]!, proof: [] }] as never, [])).rejects.toThrow(/proof/i);
});

import { createDataIntegrityProof, didToLogUrl, parseDid, verifyDataIntegrityProof } from "../packages/webvh/src/index.ts";

test("Data Integrity proofs round-trip, and refuse other keys, documents and purposes", async () => {
  const signer = key(), other = key();
  const doc = { did: "did:webvh:x", n: 1, nested: { b: 2, a: 1 } };
  const proof = await createDataIntegrityProof(doc, {
    privateKey: signer.privateKey, verificationMethod: `did:key:${signer.multikey}#${signer.multikey}`, proofPurpose: "assertionMethod", created: "2026-01-01T00:00:00Z",
  });
  expect(await verifyDataIntegrityProof(doc, proof, [signer.multikey])).toBe(true);
  expect(await verifyDataIntegrityProof({ ...doc, n: 2 }, proof, [signer.multikey])).toBe(false);
  expect(await verifyDataIntegrityProof(doc, proof, [other.multikey])).toBe(false);
  expect(await verifyDataIntegrityProof(doc, proof, [signer.multikey], "authentication")).toBe(false);
});

test("didToLogUrl/parseDid follow the did:webvh URL rules and reject hostile identifiers", () => {
  const scid = "QmNf4Y7DyYWTZcrMdQMwftYe5JmcKXfPrxpqwriHa3A7w5";
  expect(didToLogUrl(`did:webvh:${scid}:alice.did.md`)).toBe("https://alice.did.md/.well-known/did.jsonl");
  expect(didToLogUrl(`did:webvh:${scid}:example.com%3A8443:users:bob`)).toBe("https://example.com:8443/users/bob/did.jsonl");
  expect(parseDid(`did:webvh:${scid}:example.com`).scid).toBe(scid);
  for (const hostile of ["evil.com%23.did.md", "127.0.0.1", "localhost", "a.com%3Aabc"]) {
    expect(() => didToLogUrl(`did:webvh:${scid}:${hostile}`)).toThrow();
  }
  expect(() => didToLogUrl(`did:webvh:short:example.com`)).toThrow();
});

import { signWitnessProofEntry } from "didwebvh-ts";
import { fetchWitnessProofs, resolveDidWebvh, usesWitnesses } from "../packages/webvh/src/index.ts";

async function witnessedLog() {
  const [owner, next, witness] = [key(), key(), key()];
  const witnessDid = `did:key:${witness.multikey}`;
  const created = await createLog({
    domain: "example.com", signer: new Ed25519Signer(owner), updateKeys: [owner.multikey], nextKeyHashes: [await nextKeyHash(next.multikey)],
    verificationMethods: [{ id: "#k", type: "Multikey", publicKeyMultibase: owner.multikey }], authentication: ["#k"],
    witness: { threshold: 1, witnesses: [{ id: witnessDid }] },
  });
  const versionId = created.log[0]!.versionId;
  const entry = await signWitnessProofEntry({
    versionId, witnesses: [{ id: witnessDid }], witnessSignersByDid: { [witnessDid]: new Ed25519Signer(witness) },
  });
  return { created, entry, proofs: [{ versionId: entry.versionId, proof: entry.proof }] };
}

test("a witnessed log needs its did-witness.json: rejected without, accepted with; resolveDidWebvh fetches it", async () => {
  const { created, proofs } = await witnessedLog();
  expect(usesWitnesses(created.log)).toBe(true);
  await expect(resolveLog(created.log)).rejects.toThrow();
  await resolveLog(created.log, { witnessProofs: proofs as never });

  const served: Record<string, string> = {
    "https://example.com/.well-known/did.jsonl": serializeLog(created.log),
    "https://example.com/.well-known/did-witness.json": JSON.stringify(proofs),
  };
  const fakeFetch = (async (url: string) => served[url] ? new Response(served[url]) : new Response("no", { status: 404 })) as unknown as typeof fetch;
  expect((await fetchWitnessProofs("https://example.com/.well-known/did.jsonl", fakeFetch))).toHaveLength(1);
  const resolved = await resolveDidWebvh(created.did, { fetch: fakeFetch });
  expect(resolved.did).toBe(created.did);
  delete served["https://example.com/.well-known/did-witness.json"];
  await expect(resolveDidWebvh(created.did, { fetch: fakeFetch })).rejects.toThrow(/witness/);
});
