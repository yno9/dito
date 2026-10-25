/**
 * The did:vh test vectors: fixed keys and fixed times, so the output is the same
 * every time. `vectors.json` is shared with other implementations (biset keeps a
 * copy), which must give each log the stated result. Regenerate with
 *
 *   node packages/vh/vectors/generate.ts > packages/vh/vectors/vectors.json
 *
 * tests/vh-vectors.test.ts fails if the file and this script disagree. biset keeps a copy that its own tests run against:
 *
 *   cp packages/vh/vectors/vectors.json ../biset/test/fixtures/did-vh-vectors.json
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { multibaseBase58 } from "../src/base58.ts";
import { createDataIntegrityProof } from "../src/proof.ts";
import { keyFromPrivateKey } from "../src/signer.ts";
import { createVhLog, deactivateVhLog, deriveDidWebDocument, entryHash, keyHash, updateVhLog, type VhLogEntry } from "../src/index.ts";

const key = (label: string) => keyFromPrivateKey(sha256(new TextEncoder().encode(`did:vh test vector key ${label}`)));
const [k0, k1, k2, k3] = [key("0"), key("1"), key("2"), key("3")] as const;
const T0 = Date.parse("2026-01-01T00:00:00Z");
const NOW = "2026-06-01T00:00:00Z";
const at = (seconds: number) => T0 + seconds * 1000;

/** `reason` is a phrase of the message this implementation gives; other implementations compare `code` only. */
type Expectation = { ok: true; versionNumber: number; deactivated: boolean; documentNull?: boolean } | { ok: false; code: string; reason: string };
type Vector = { name: string; note: string; did: string; log: VhLogEntry[]; options?: Record<string, unknown>; expect: Expectation };

const document = (did: string, extra: Record<string, unknown> = {}) => ({
  "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"], id: did,
  verificationMethod: [{ id: `${did}#k`, type: "Multikey", controller: did, publicKeyMultibase: k0.multikey }], authentication: [`${did}#k`], ...extra,
});

/** A correctly signed entry appended without any of the library's checks, to build logs a resolver must refuse. */
async function append(log: VhLogEntry[], signer: typeof k0, seconds: number, parameters: Record<string, unknown>, state?: Record<string, unknown>, tweaks: { before?: (unsigned: any) => void; after?: (entry: any) => void } = {}): Promise<VhLogEntry[]> {
  const last = log[log.length - 1]!;
  const versionTime = `${new Date(at(seconds)).toISOString().slice(0, 19)}Z`;
  const unsigned: any = { versionId: last.versionId, versionTime, parameters, state: state ?? structuredClone(last.state) };
  tweaks.before?.(unsigned);
  const entry: any = { ...unsigned, versionId: `${log.length + 1}-${entryHash(unsigned as never, last.versionId)}` };
  tweaks.after?.(entry);
  const proof = await createDataIntegrityProof(entry, { privateKey: signer.privateKey, verificationMethod: `did:key:${signer.multikey}#${signer.multikey}`, proofPurpose: "assertionMethod", created: entry.versionTime });
  return [...log, { ...entry, proof: [proof] }];
}

/** A did:web document offered for a did:vh document, and whether a verifier must accept it as that document's shadow. */
type ShadowVector = { name: string; note: string; vhDocument: Record<string, unknown>; didWeb: string; webDocument: unknown; ok: boolean };

function shadowVectors(): ShadowVector[] {
  const scid = "Q".repeat(46);
  const did = `did:vh:${scid}`;
  const webDid = "did:web:alice.did.md";
  const key = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
  const vh: Record<string, any> = {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"], id: did, controller: did,
    alsoKnownAs: [webDid, `${did}?src=https://alice.did.md`, "https://example.org/alice"], name: "Alice",
    verificationMethod: [{ id: `${did}#k`, type: "Multikey", controller: did, publicKeyMultibase: key }, { id: "#rel", type: "Multikey", controller: did, publicKeyMultibase: key }],
    authentication: [`${did}#k`, "#rel"], assertionMethod: ["#rel"],
    service: [{ id: `${did}#wallet`, type: "SelfIssuedOPAuthorizationEndpoint", serviceEndpoint: "https://dito.did.md/authorize" }, { id: "#files", type: "relativeRef", serviceEndpoint: { uri: `https://alice.did.md/x/${did}/y`, accept: [did] } }],
  };
  const shadow = deriveDidWebDocument(vh, webDid);
  const out: ShadowVector[] = [];
  const add = (name: string, note: string, webDocument: unknown, ok: boolean, options: { vhDocument?: Record<string, unknown>; didWeb?: string } = {}) =>
    out.push({ name, note, vhDocument: options.vhDocument ?? vh, didWeb: options.didWeb ?? webDid, webDocument, ok });
  add("valid/derived", "The derivation: the DID replaced in ids, controllers and references (also followed by #, ? or /), alsoKnownAs reduced to the did:vh DID with the location as its src, relative references and other strings untouched.", shadow, true);
  add("invalid/extra-member", "A member the derivation does not give.", { ...shadow, extra: 1 }, false);
  add("invalid/missing-member", "A member the derivation gives is missing.", (({ name: _name, ...rest }) => rest)(shadow as any), false);
  add("invalid/other-key", "A verification key that is not the did:vh document's.", { ...shadow, verificationMethod: [{ ...shadow.verificationMethod[0], publicKeyMultibase: "z6MkuDdJdKLCgwZuQuEi9xG6LVgJJ9Tebr74CXPYPSumqgJs" }, shadow.verificationMethod[1]] }, false);
  add("invalid/extra-service", "A service the did:vh document does not have.", { ...shadow, service: [...shadow.service, { id: "#x", type: "X", serviceEndpoint: "https://evil.example" }] }, false);
  add("invalid/also-known-as-extra", "alsoKnownAs names more than the did:vh DID.", { ...shadow, alsoKnownAs: [did, "https://evil.example"] }, false);
  add("invalid/also-known-as-keeps-vh-document-names", "alsoKnownAs copied from the did:vh document instead of reduced.", { ...shadow, alsoKnownAs: vh.alsoKnownAs }, false);
  add("invalid/also-known-as-another-did", "alsoKnownAs names another did:vh.", { ...shadow, alsoKnownAs: [`did:vh:${"1".repeat(46)}`] }, false);
  add("invalid/id-not-the-web-did", "The document's id is another did:web.", { ...shadow, id: "did:web:evil.example" }, false);
  add("invalid/vh-id-left-in-place", "The did:vh DID was not replaced.", vh, false);
  add("invalid/vh-document-does-not-name-the-web-did", "The did:vh document does not list this did:web DID: the link is one-way.", shadow, false, { didWeb: "did:web:bob.did.md" });
  add("invalid/vh-document-names-nothing", "The did:vh document lists no alias at all.", shadow, false, { vhDocument: { ...vh, alsoKnownAs: [] } });
  add("invalid/not-an-object", "Not a document.", "did:web:alice.did.md", false);
  add("invalid/null", "null.", null, false);
  add("invalid/array", "An array.", [shadow], false);
  return out;
}

export async function vectors(): Promise<{ now: string; vectors: Vector[]; shadows: ShadowVector[] }> {
  const plain = await createVhLog({ signer: k0, updateKeys: [k0.multikey], document: did => document(did), now: at(0) });
  const pre = await createVhLog({ signer: k0, updateKeys: [k0.multikey], nextKeyHashes: [keyHash(k1.multikey)], document: did => document(did), now: at(0) });
  const out: Vector[] = [];
  const add = (name: string, note: string, did: string, log: VhLogEntry[], expectation: Expectation, options?: Record<string, unknown>) => out.push({ name, note, did, log, ...(options ? { options } : {}), expect: expectation });

  // ---- valid ----------------------------------------------------------------------------------------------------
  add("valid/single-entry", "A created log.", plain.did, plain.log, { ok: true, versionNumber: 1, deactivated: false });

  // A DIDComm-capable document: an X25519 key agreement key (multicodec 0xec01), a service. Its keys are fixed, so other implementations can check what they read from it.
  const agreementKey = multibaseBase58(new Uint8Array([0xec, 0x01, ...sha256(new TextEncoder().encode("did:vh test vector key agreement"))]));
  const withAgreement = await createVhLog({
    signer: k0, updateKeys: [k0.multikey], document: did => document(did, {
      verificationMethod: [{ id: `${did}#k`, type: "Multikey", controller: did, publicKeyMultibase: k0.multikey }, { id: `${did}#ka`, type: "Multikey", controller: did, publicKeyMultibase: agreementKey }],
      keyAgreement: [`${did}#ka`],
      service: [{ id: `${did}#didcomm`, type: "DIDCommMessaging", serviceEndpoint: { uri: "https://mediator.example/" } }],
    }), now: at(0),
  });
  add("valid/key-agreement", "A document with an X25519 keyAgreement key and a DIDComm service (what a mediator reads).", withAgreement.did, withAgreement.log, { ok: true, versionNumber: 1, deactivated: false });

  const rotated = await updateVhLog({ log: plain.log, signer: k0, parameters: { updateKeys: [k1.multikey] }, now: at(10) });
  const rotated2 = await updateVhLog({ log: rotated.log, signer: k1, document: { ...rotated.log[1]!.state, service: [{ id: `${plain.did}#s`, type: "S", serviceEndpoint: "https://s.example" }] }, now: at(20) });
  add("valid/rotation-without-prerotation", "Entry 2 is signed by the keys of entry 1 and introduces k1; entry 3 is signed by k1.", plain.did, rotated2.log, { ok: true, versionNumber: 3, deactivated: false });
  add("valid/version-number", "Selecting version 2 of three.", plain.did, rotated2.log, { ok: true, versionNumber: 2, deactivated: false }, { versionNumber: 2 });

  const p2 = await updateVhLog({ log: pre.log, signer: k1, parameters: { updateKeys: [k1.multikey], nextKeyHashes: [keyHash(k2.multikey)] }, now: at(10) });
  const p3 = await updateVhLog({ log: p2.log, signer: k2, parameters: { updateKeys: [k2.multikey], nextKeyHashes: [] }, now: at(20) });
  add("valid/prerotation", "Each entry is signed by a key the entry before committed to; the last ends pre-rotation.", pre.did, p3.log, { ok: true, versionNumber: 3, deactivated: false });

  const done = await deactivateVhLog({ log: plain.log, signer: k0, now: at(10) });
  add("valid/deactivated", "The latest version of a deactivated DID has no document.", plain.did, done.log, { ok: true, versionNumber: 2, deactivated: true, documentNull: true });
  add("valid/deactivated-earlier-version", "An earlier version of a deactivated DID still resolves, flagged deactivated.", plain.did, done.log, { ok: true, versionNumber: 1, deactivated: true }, { versionNumber: 1 });

  // ---- invalid --------------------------------------------------------------------------------------------------
  const bad = (name: string, note: string, log: VhLogEntry[], reason: string, extra: { code?: string; did?: string; options?: Record<string, unknown> } = {}) =>
    add(`invalid/${name}`, note, extra.did ?? log[0]!.state.id, log, { ok: false, code: extra.code ?? "invalidLog", reason }, extra.options);

  const edited = structuredClone(plain.log);
  edited[0]!.state.alsoKnownAs = ["https://evil.example"];
  bad("first-entry-edited", "The document of the first entry was changed after the SCID was computed.", edited, "SCID does not match");
  const editedLater = structuredClone(rotated.log);
  editedLater[1]!.state = { ...editedLater[1]!.state, alsoKnownAs: ["https://evil.example"] };
  bad("later-entry-edited", "The document of a later entry was changed: its entry hash no longer matches.", editedLater, "entry hash");
  bad("other-did", "A valid log, presented for a different SCID.", plain.log, "not the SCID of the DID", { did: `did:vh:${"1".repeat(46)}` });
  bad("not-a-vh-did", "The DID is of another method.", plain.log, "Not a did:vh", { code: "invalidDid", did: "did:web:example.com" });
  bad("unsigned", "An entry with no proof.", [plain.log[0]!, { ...rotated.log[1]!, proof: [] }], "no proof");
  bad("signed-by-unauthorised-key", "Entry 2 is signed by k3, which no entry authorised.", await append(plain.log, k3, 10, {}), "authorised key");
  bad("signed-by-previous-keys-after-rotation", "Entry 3 is signed by k0 although entry 2 replaced k0 with k1.", await append(rotated.log, k0, 20, {}), "authorised key");
  bad("prerotation-uncommitted-key", "Entry 2 authorises k3, which entry 1 did not commit to.", await append(pre.log, k3, 10, { updateKeys: [k3.multikey], nextKeyHashes: [] }), "did not commit");
  bad("prerotation-update-keys-not-restated", "Entry 2 omits updateKeys while pre-rotation is active.", await append(pre.log, k1, 10, { nextKeyHashes: [] }), "restate updateKeys");
  bad("prerotation-next-key-hashes-not-restated", "Entry 2 omits nextKeyHashes while pre-rotation is active.", await append(pre.log, k1, 10, { updateKeys: [k1.multikey] }), "restate nextKeyHashes");
  bad("version-number-gap", "Entry 2 is numbered 3.", await append(plain.log, k0, 10, {}, undefined, { after: entry => { entry.versionId = entry.versionId.replace(/^2-/, "3-"); } }), "version number");
  bad("time-not-increasing", "Entry 2 has the same versionTime as entry 1.", await append(plain.log, k0, 0, {}), "not later");
  bad("time-in-the-future", "Entry 2 is a year after the resolver's now.", await append(plain.log, k0, 60 * 60 * 24 * 365 * 2, {}), "future");
  bad("time-with-fraction", "Entry 2's versionTime has fractional seconds.", await append(plain.log, k0, 10, {}, undefined, { before: unsigned => { unsigned.versionTime = unsigned.versionTime.replace("Z", ".500Z"); } }), "whole seconds");
  bad("document-id-is-the-did-with-src", "Entry 2's document id carries a ?src=.", await append(plain.log, k0, 10, {}, { ...plain.log[0]!.state, id: `${plain.did}?src=https://alice.did.md` }), "document id must be exactly");
  bad("document-id-is-another-did", "Entry 2's document id is another did:vh.", await append(plain.log, k0, 10, {}, { ...plain.log[0]!.state, id: `did:vh:${"1".repeat(46)}` }), "document id must be exactly");
  bad("portable", "A parameter of another DID method, which did:vh does not define.", await append(plain.log, k0, 10, { portable: true }), "portable");
  bad("log-version", "VH-Log's own version parameter, which a specialisation that designates its own must not use.", await append(plain.log, k0, 10, { logVersion: "vh-log:1.0" }), "logVersion");
  bad("unknown-parameter", "A parameter did:vh does not define.", await append(plain.log, k0, 10, { color: "red" }), "not a did:vh parameter");
  bad("null-parameter", "null stands for nothing in a parameter.", await append(plain.log, k0, 10, { ttl: null }), "null");
  bad("method-is-another", "The method of another DID method.", await append(plain.log, k0, 10, { method: "did:web:1.0" }), "Unsupported method");
  bad("scid-in-later-entry", "parameters.scid in a later entry.", await append(plain.log, k0, 10, { scid: plain.did.slice(7) }), "scid may only appear");
  bad("entry-after-deactivation", "An entry follows the deactivating entry.", await append(done.log, k0, 20, {}), "deactivated");
  bad("witness-not-supported", "A witness configuration is refused rather than ignored.", await append(plain.log, k0, 10, { witness: { threshold: 1, witnesses: [{ id: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" }] } }), "witnesses", { code: "featureNotSupported" });
  bad("two-version-selectors", "More than one of versionId, versionTime and versionNumber.", plain.log, "At most one", { code: "invalidOptions", options: { versionNumber: 1, versionId: plain.log[0]!.versionId } });
  bad("version-not-found", "A version the log does not have.", plain.log, "No entry", { code: "notFound", options: { versionNumber: 2 } });
  return { now: NOW, vectors: out, shadows: shadowVectors() };
}

if (process.argv[1]?.endsWith("vectors/generate.ts")) {
  process.stdout.write(`${JSON.stringify(await vectors(), null, 1)}\n`);
}
