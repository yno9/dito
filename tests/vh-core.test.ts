import { expect, test } from "vitest";
import { Ed25519Signer, createLog, keyFromPrivateKey, nextKeyHash } from "../packages/webvh/src/index.ts";
import {
  SCID_PLACEHOLDER, VH_METHOD, VhResolutionError, canonicalize, createVhLog, deactivateVhLog, entryHash, jcsHash, keyHash, parseVersionId,
  parseVhDid, parseVhLog, resolveVhLog, serializeVhLog, updateVhLog, verifyScid, vhDid, type VhLogEntry,
} from "../packages/vh/src/index.ts";

const key = () => keyFromPrivateKey(crypto.getRandomValues(new Uint8Array(32)));
const document = (extra: Record<string, any> = {}) => (did: string) => ({ "@context": ["https://www.w3.org/ns/did/v1"], id: did, ...extra });

// ---- the specification's own vector -------------------------------------------------------------------------------

test("the entry hash of did:webvh v1.0's worked example is the one that specification states", () => {
  // https://identity.foundation/didwebvh/v1.0/#generate-entry-hash (the algorithm did:vh shares).
  const preliminary = {"versionId": "QmdmPkUdYzbr9txmx8gM2rsHPgr5L6m3gHjJGAf4vUFoGE", "versionTime": "2025-04-01T17:39:50Z", "parameters": {"witness": {"threshold": 2, "witnesses": [{"id": "did:key:z6Mkkc51mg2vpQzKWAbWQZupeGYhowaBjYkmvcKMTqteqHB4", "weight": 1}, {"id": "did:key:z6MkuDdJdKLCgwZuQuEi9xG6LVgJJ9Tebr74CXPYPSumqgJs", "weight": 1}, {"id": "did:key:z6MkoSWmQyp4fTk4ZQy4KUsss9dFX51XfEUzKKKj1J1JUsrF", "weight": 1}]}, "updateKeys": ["z6MkgzBDcBFV3sk4ypPE5YXMZHmS213A3HpYY2LmcVKV15jr"], "nextKeyHashes": ["QmZreDcjvWEpyRFznQeExWNCsvMLk5i59AcRJJuQC8UodJ"], "method": "did:webvh:0.5", "scid": "QmdmPkUdYzbr9txmx8gM2rsHPgr5L6m3gHjJGAf4vUFoGE"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmdmPkUdYzbr9txmx8gM2rsHPgr5L6m3gHjJGAf4vUFoGE:domain.example"}};
  expect(jcsHash(preliminary)).toBe("QmQ6FJ4fk2xheSSQoEjVpTgx9AQPKhJgtR9hn1nr4EeCrZ");
});

test("VH-Log's own copy of that example does not reproduce its stated hash (its input was edited, the hash was not recomputed)", () => {
  // Recorded so that a future correction upstream shows up here: the parameters name `logVersion` and the state is `example:…`.
  const edited = {"versionId": "QmdmPkUdYzbr9txmx8gM2rsHPgr5L6m3gHjJGAf4vUFoGE", "versionTime": "2025-04-01T17:39:50Z", "parameters": {"witness": {"threshold": 2, "witnesses": [{"id": "witness-1"}, {"id": "witness-2"}, {"id": "witness-3"}]}, "updateKeys": ["z6MkgzBDcBFV3sk4ypPE5YXMZHmS213A3HpYY2LmcVKV15jr"], "nextKeyHashes": ["QmZreDcjvWEpyRFznQeExWNCsvMLk5i59AcRJJuQC8UodJ"], "logVersion": "vh-log:1.0", "scid": "QmdmPkUdYzbr9txmx8gM2rsHPgr5L6m3gHjJGAf4vUFoGE"}, "state": {"id": "example:QmdmPkUdYzbr9txmx8gM2rsHPgr5L6m3gHjJGAf4vUFoGE"}};
  expect(jcsHash(edited)).not.toBe("QmQ6FJ4fk2xheSSQoEjVpTgx9AQPKhJgtR9hn1nr4EeCrZ");
});

test("JCS sorts keys by UTF-16 code unit, drops undefined members, and writes -0 as 0", () => {
  expect(canonicalize({ b: 1, a: [true, null, "x"], "é": 1, "z": undefined })).toBe('{"a":[true,null,"x"],"b":1,"é":1}');
  expect(canonicalize({ n: -0, m: 1e21, k: 0.5 })).toBe('{"k":0.5,"m":1e+21,"n":0}');
  expect(() => canonicalize({ n: NaN })).toThrow();
});

test("keyHash is didwebvh-ts's pre-rotation hash", async () => {
  const k = key().multikey;
  expect(keyHash(k)).toBe(await nextKeyHash(k));
});

// ---- the same algorithms as did:webvh: a didwebvh-ts log checks out with these functions ---------------------------

test("the SCID and entry hashes of a log made by didwebvh-ts verify with did:vh's functions", async () => {
  const [k0, k1] = [key(), key()];
  const created = await createLog({
    domain: "example.com", signer: new Ed25519Signer(k0), updateKeys: [k0.multikey], nextKeyHashes: [await nextKeyHash(k1.multikey)],
    verificationMethods: [{ id: "#k", type: "Multikey", publicKeyMultibase: k0.multikey }], authentication: ["#k"],
  });
  const first = created.log[0] as unknown as VhLogEntry;
  expect(verifyScid(first)).toBe(true);
  expect(`1-${entryHash(first, first.parameters.scid!)}`).toBe(first.versionId);
  const tampered = structuredClone(first);
  tampered.state = { ...tampered.state, alsoKnownAs: ["https://evil.example"] };
  expect(verifyScid(tampered)).toBe(false);
});

// ---- identifiers --------------------------------------------------------------------------------------------------

test("did:vh syntax: the whole identifier is a 46-character base58btc SCID", async () => {
  const { did } = await createVhLog({ signer: key(), updateKeys: [], document: document() }).catch(() => ({ did: "" }));
  expect(did).toBe("");
  const created = await newLog();
  expect(created.did).toMatch(/^did:vh:[1-9A-HJ-NP-Za-km-z]{46}$/);
  expect(parseVhDid(created.did).scid).toBe(created.did.slice(7));
  for (const bad of ["did:vh:", "did:vh:short", `${created.did}#k`, `${created.did}?src=https://a.example`, `${created.did}:x`, created.did.replace("did:vh", "did:webvh"), `did:vh:${"0".repeat(46)}`]) {
    expect(() => parseVhDid(bad), bad).toThrow();
  }
  expect(vhDid(SCID_PLACEHOLDER)).toBe("did:vh:{SCID}");
  expect(parseVersionId("12-QmAbc")).toEqual({ number: 12, hash: "QmAbc" });
  for (const bad of ["", "0-Qm", "01-Qm", "1", "1-", "1--Qm", "1-Qm-x", "-Qm"]) expect(() => parseVersionId(bad), bad).toThrow();
});

// ---- creating, updating, resolving --------------------------------------------------------------------------------

async function newLog(options: { pre?: boolean } = {}) {
  const [k0, k1, k2, k3] = [key(), key(), key(), key()];
  const created = await createVhLog({
    signer: k0, updateKeys: [k0.multikey], ...(options.pre ? { nextKeyHashes: [keyHash(k1.multikey)] } : {}),
    document: did => ({ "@context": ["https://www.w3.org/ns/did/v1"], id: did, verificationMethod: [{ id: `${did}#k`, type: "Multikey", controller: did, publicKeyMultibase: k0.multikey }], authentication: [`${did}#k`] }),
  });
  return { ...created, k0, k1, k2, k3 };
}

test("a created log resolves; the SCID is in the DID, in every id and in parameters.scid", async () => {
  const { did, log } = await newLog();
  const scid = did.slice(7);
  expect(log).toHaveLength(1);
  expect(log[0]!.parameters).toMatchObject({ method: VH_METHOD, scid });
  expect(JSON.stringify(log)).not.toContain(SCID_PLACEHOLDER);
  expect(log[0]!.state.verificationMethod[0].id).toBe(`${did}#k`);
  const resolved = await resolveVhLog(did, log);
  expect(resolved.doc).toEqual(log[0]!.state);
  expect(resolved.meta).toMatchObject({ versionNumber: 1, deactivated: false, ttl: 3600, scid, created: log[0]!.versionTime });
});

test("the log survives its own file form", async () => {
  const { did, log } = await newLog();
  expect(parseVhLog(serializeVhLog(log))).toEqual(log);
  expect(parseVhLog(serializeVhLog(log).trimEnd())).toEqual(log);
  expect(() => parseVhLog("")).toThrow();
  expect(() => parseVhLog(`${JSON.stringify(log[0])}\n\n${JSON.stringify(log[0])}\n`)).toThrow(/line 2/);
  await resolveVhLog(did, parseVhLog(serializeVhLog(log)));
});

test("an update does not share its document with the entry before", async () => {
  const { log, k0 } = await newLog();
  const { log: next } = await updateVhLog({ log, signer: k0, now: Date.now() + 2000 });
  expect(next[1]!.state).toEqual(next[0]!.state);
  expect(next[1]!.state).not.toBe(next[0]!.state);
});

test("update without pre-rotation: the previous entry's keys sign; the new keys sign the one after", async () => {
  const { did, log, k0, k1 } = await newLog();
  const second = await updateVhLog({ log, signer: k0, parameters: { updateKeys: [k1.multikey] }, now: Date.now() + 2000 });
  // The entry that introduced k1 was signed by k0 (the keys of the entry before).
  const third = await updateVhLog({ log: second.log, signer: k1, document: { ...second.log[1]!.state, service: [{ id: `${did}#s`, type: "S", serviceEndpoint: "https://s.example" }] }, now: Date.now() + 4000 });
  const resolved = await resolveVhLog(did, third.log);
  expect(resolved.meta.versionNumber).toBe(3);
  expect(resolved.doc!.service).toHaveLength(1);
  // k0 no longer authorises anything.
  await expect(updateVhLog({ log: third.log, signer: k0, now: Date.now() + 6000 })).rejects.toThrow(/authorised key/);
  // A version can be asked for by number, id, or time.
  expect((await resolveVhLog(did, third.log, { versionNumber: 1 })).doc).toEqual(log[0]!.state);
  expect((await resolveVhLog(did, third.log, { versionId: third.log[1]!.versionId })).meta.versionNumber).toBe(2);
  expect((await resolveVhLog(did, third.log, { versionTime: third.log[1]!.versionTime })).meta.versionNumber).toBe(2);
  await expect(resolveVhLog(did, third.log, { versionNumber: 4 })).rejects.toMatchObject({ code: "notFound" });
  await expect(resolveVhLog(did, third.log, { versionNumber: 1, versionId: log[0]!.versionId })).rejects.toMatchObject({ code: "invalidOptions" });
});

test("update with pre-rotation: the entry is signed by a key the entry before committed to, and restates both lists", async () => {
  const { did, log, k0, k1, k2, k3 } = await newLog({ pre: true });
  const second = await updateVhLog({ log, signer: k1, parameters: { updateKeys: [k1.multikey], nextKeyHashes: [keyHash(k2.multikey)] }, now: Date.now() + 2000 });
  // Not committed: refused.
  await expect(updateVhLog({ log: second.log, signer: k3, parameters: { updateKeys: [k3.multikey], nextKeyHashes: [keyHash(key().multikey)] }, now: Date.now() + 4000 })).rejects.toThrow(/did not commit/);
  // The old key cannot sign either, even though it is the one that created the log.
  await expect(updateVhLog({ log: second.log, signer: k0, parameters: { updateKeys: [k0.multikey], nextKeyHashes: [] }, now: Date.now() + 4000 })).rejects.toThrow();
  // Omitting a list that must be restated is refused.
  await expect(updateVhLog({ log: second.log, signer: k2, parameters: { updateKeys: [k2.multikey] }, now: Date.now() + 4000 })).rejects.toThrow(/restate nextKeyHashes/);
  await expect(updateVhLog({ log: second.log, signer: k2, parameters: { nextKeyHashes: [keyHash(k3.multikey)] }, now: Date.now() + 4000 })).rejects.toThrow(/restate updateKeys/);
  const third = await updateVhLog({ log: second.log, signer: k2, parameters: { updateKeys: [k2.multikey], nextKeyHashes: [] }, now: Date.now() + 4000 });
  expect((await resolveVhLog(did, third.log)).meta.versionNumber).toBe(3);
  // Pre-rotation is over: the next entry is signed by the keys of the entry before (k2 again).
  const fourth = await updateVhLog({ log: third.log, signer: k2, now: Date.now() + 6000 });
  expect(fourth.log).toHaveLength(4);
});

test("deactivation: no document for the latest version, one for the earlier versions, and nothing may follow", async () => {
  const { did, log, k0 } = await newLog();
  const done = await deactivateVhLog({ log, signer: k0, now: Date.now() + 2000 });
  const latest = await resolveVhLog(did, done.log);
  expect(latest.doc).toBeNull();
  expect(latest.meta.deactivated).toBe(true);
  const earlier = await resolveVhLog(did, done.log, { versionNumber: 1 });
  expect(earlier.doc).toEqual(log[0]!.state);
  expect(earlier.meta.deactivated).toBe(true);
  await expect(updateVhLog({ log: done.log, signer: k0, now: Date.now() + 4000 })).rejects.toThrow(/deactivated/);
});

test("deactivation under pre-rotation ends the commitment with the committed key", async () => {
  const { did, log, k1 } = await newLog({ pre: true });
  const done = await deactivateVhLog({ log, signer: k1, now: Date.now() + 2000 });
  expect(done.log[1]!.parameters).toEqual({ deactivated: true, updateKeys: [k1.multikey], nextKeyHashes: [] });
  expect((await resolveVhLog(did, done.log)).doc).toBeNull();
});

// ---- what a resolver must refuse ----------------------------------------------------------------------------------

async function refuses(did: string, log: VhLogEntry[], pattern: RegExp | string) {
  await expect(resolveVhLog(did, log)).rejects.toThrow(pattern);
}

test("a log that is not the DID's is refused", async () => {
  const a = await newLog();
  const b = await newLog();
  await refuses(a.did, b.log, /SCID in the log is not the SCID/);
  await expect(resolveVhLog("did:webvh:abc", a.log)).rejects.toMatchObject({ code: "invalidDid" });
  await expect(resolveVhLog(`${a.did}#k`, a.log)).rejects.toMatchObject({ code: "invalidDid" });
});

test("tampering is refused: the document, the SCID, the hash chain, the proof", async () => {
  const { did, log, k0, k1 } = await newLog();
  const second = (await updateVhLog({ log, signer: k0, parameters: { updateKeys: [k1.multikey] }, now: Date.now() + 2000 })).log;

  const changedDocument = structuredClone(second);
  changedDocument[0]!.state.alsoKnownAs = ["https://evil.example"];
  await refuses(did, changedDocument, /SCID does not match|entry hash/);

  const changedLater = structuredClone(second);
  changedLater[1]!.state.alsoKnownAs = ["https://evil.example"];
  await refuses(did, changedLater, /entry hash/);

  const reordered = [second[1]!, second[0]!];
  await refuses(did, reordered, /./);

  const gap = [second[0]!, { ...second[1]!, versionId: `3-${second[1]!.versionId.split("-")[1]}` }];
  await refuses(did, gap, /version number/);

  const wrongSigner = structuredClone(second);
  wrongSigner[1]!.proof[0]!.proofValue = log[0]!.proof[0]!.proofValue;
  await refuses(did, wrongSigner, /proof/);

  const unsigned = structuredClone(second);
  unsigned[1]!.proof = [];
  await refuses(did, unsigned, /no proof/);
});

test("the document id must be exactly the DID in every entry (a did:webvh id, a ?src= id, another SCID)", async () => {
  const { did, log, k0 } = await newLog();
  for (const id of [`${did}?src=https://a.example`, "did:webvh:Qm:example.com", `did:vh:${"1".repeat(46)}`, `${did}#x`]) {
    const next = await updateVhLogUnchecked(log, k0, { ...log[0]!.state, id });
    await refuses(did, next, /document id must be exactly/);
  }
});

test("parameters: portable, logVersion, null, unknown names, a wrong method, and a late scid are refused", async () => {
  const { did, log, k0 } = await newLog();
  const cases: Array<[Record<string, unknown>, RegExp]> = [
    [{ portable: true }, /portable/], [{ portable: false }, /portable/], [{ logVersion: "vh-log:1.0" }, /logVersion/],
    [{ ttl: null }, /null/], [{ method: "did:webvh:1.0" }, /Unsupported method/], [{ method: "did:vh:2.0" }, /Unsupported method/],
    [{ scid: "x" }, /scid may only appear/], [{ unknown: 1 }, /not a did:vh parameter/], [{ ttl: -1 }, /ttl/], [{ ttl: 1.5 }, /ttl/],
    [{ deactivated: "yes" }, /deactivated/], [{ watchers: ["http://w.example"] }, /https/], [{ updateKeys: ["z6Mknotakey"] }, /Ed25519/],
    [{ nextKeyHashes: "x" }, /array of strings/],
  ];
  for (const [parameters, pattern] of cases) await refuses(did, await updateVhLogUnchecked(log, k0, undefined, parameters), pattern);
});

test("the first entry must carry method, scid and updateKeys; an unknown member of an entry is refused", async () => {
  const { did, log } = await newLog();
  const withoutMethod = structuredClone(log);
  delete withoutMethod[0]!.parameters.method;
  await refuses(did, withoutMethod, /method/);
  await refuses(did, [{ ...log[0]!, extra: 1 } as VhLogEntry], /unknown member/);
});

test("witnesses are refused, not ignored", async () => {
  const { did, log, k0 } = await newLog();
  const witnessed = await updateVhLogUnchecked(log, k0, undefined, { witness: { threshold: 1, witnesses: [{ id: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" }] } });
  await expect(resolveVhLog(did, witnessed)).rejects.toMatchObject({ code: "featureNotSupported" });
});

test("times: not later than the entry before, not in the future, whole seconds, UTC", async () => {
  const { did, log, k0 } = await newLog();
  await refuses(did, await updateVhLogUnchecked(log, k0, undefined, {}, log[0]!.versionTime), /not later/);
  await refuses(did, await updateVhLogUnchecked(log, k0, undefined, {}, "2999-01-01T00:00:00Z"), /future/);
  await refuses(did, await updateVhLogUnchecked(log, k0, undefined, {}, "2030-01-01T00:00:00.500Z"), /whole seconds/);
  await refuses(did, await updateVhLogUnchecked(log, k0, undefined, {}, "2030-01-01T09:00:00+09:00"), /UTC/);
});

/** A log with one more entry, signed correctly but NOT checked by the library, so the resolver's refusal can be tested. */
async function updateVhLogUnchecked(log: VhLogEntry[], signer: ReturnType<typeof key>, document?: Record<string, any>, parameters: Record<string, unknown> = {}, versionTime?: string): Promise<VhLogEntry[]> {
  const { createDataIntegrityProof } = await import("../packages/webvh/src/proof.ts");
  const last = log[log.length - 1]!;
  const time = versionTime ?? new Date(Date.parse(last.versionTime) + 2000).toISOString().slice(0, 19) + "Z";
  const unsigned = { versionId: last.versionId, versionTime: time, parameters, state: document ?? last.state };
  const versionId = `${log.length + 1}-${entryHash(unsigned as never, last.versionId)}`;
  const entry = { ...unsigned, versionId };
  const proof = await createDataIntegrityProof(entry, { privateKey: signer.privateKey, verificationMethod: `did:key:${signer.multikey}#${signer.multikey}`, proofPurpose: "assertionMethod", created: time });
  return [...log, { ...entry, proof: [proof] } as VhLogEntry];
}

test("an error from the resolver carries a code", async () => {
  const { log } = await newLog();
  const error = await resolveVhLog("did:vh:nope", log).catch(e => e);
  expect(error).toBeInstanceOf(VhResolutionError);
  expect(error.code).toBe("invalidDid");
});

// ---- what a host checks before it stores a log ---------------------------------------------------------------------

test("validateVhLogAt: a valid log, the parameters in force, and the location rule", async () => {
  const { validateVhLogAt } = await import("../packages/vh/src/index.ts");
  const k0 = key(), k1 = key();
  const web = "did:web:alice.did.md";
  const { did, log } = await createVhLog({ signer: k0, updateKeys: [k0.multikey], nextKeyHashes: [keyHash(k1.multikey)], document: d => ({ id: d, alsoKnownAs: [web] }) });
  const checked = await validateVhLogAt(log, { webDid: web });
  expect(checked.did).toBe(did);
  expect(checked.latest).toBe(log[0]);
  expect(checked.parameters).toMatchObject({ scid: did.slice(7), updateKeys: [k0.multikey], nextKeyHashes: [keyHash(k1.multikey)], portable: false, deactivated: false });
  await validateVhLogAt(log);
  // The location rule: the current document must name this location's did:web DID.
  await expect(validateVhLogAt(log, { webDid: "did:web:bob.did.md" })).rejects.toThrow(/must name did:web:bob\.did\.md/);
  const renamed = await updateVhLog({ log, signer: k1, document: { id: did, alsoKnownAs: ["did:web:bob.did.md"] }, parameters: { updateKeys: [k1.multikey], nextKeyHashes: [] }, now: Date.now() + 2000 });
  await expect(validateVhLogAt(renamed.log, { webDid: web })).rejects.toThrow(/must name/);
  await validateVhLogAt(renamed.log, { webDid: "did:web:bob.did.md" });
  // A deactivated DID no longer has to name anything.
  const done = await deactivateVhLog({ log: renamed.log, signer: k1, now: Date.now() + 4000 });
  expect((await validateVhLogAt(done.log, { webDid: web })).parameters.deactivated).toBe(true);
  // Bad logs are the resolver's errors.
  await expect(validateVhLogAt([])).rejects.toThrow(/number of log entries/);
  await expect(validateVhLogAt([{ ...log[0]!, parameters: { ...log[0]!.parameters, scid: "x" } }])).rejects.toThrow(/valid SCID/);
});
