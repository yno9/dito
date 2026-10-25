/**
 * The did:vh part of SPEC-webvh-hosting.md §7: black-box checks for a host that
 * advertises `"did:vh"` in `methods` of `/.well-known/did-hosting.json`. A host
 * that does not is not asked (the base suite, `runConformance`, is all it owes).
 * Run it with the same target as the base suite.
 */
import type { ConformanceResult, ConformanceTarget } from "../../webvh/src/conformance.ts";
import { createDataIntegrityProof } from "../../webvh/src/proof.ts";
import { keyFromPrivateKey, type Ed25519Key } from "../../webvh/src/signer.ts";
import { createVhLog, deactivateVhLog, updateVhLog } from "./create.ts";
import { checkDidWebShadow, didWebFor } from "./didweb.ts";
import { keyHash } from "./hash.ts";
import { serializeVhLog, type VhLogEntry } from "./log.ts";

const key = () => keyFromPrivateKey(crypto.getRandomValues(new Uint8Array(32)));

/** Does the host advertise did:vh? (`methods` in its capability document.) */
export async function advertisesVh(target: ConformanceTarget): Promise<boolean> {
  try {
    const response = await target.fetch(`https://${target.newLocation()}/.well-known/did-hosting.json`);
    if (!response.ok) return false;
    const caps = await response.json() as { methods?: unknown };
    return Array.isArray(caps.methods) && caps.methods.includes("did:vh");
  } catch { return false; }
}

export async function runVhConformance(target: ConformanceTarget): Promise<ConformanceResult[]> {
  const results: ConformanceResult[] = [];
  const check = async (name: string, fn: () => Promise<void>) => {
    try { await fn(); results.push({ name, ok: true }); }
    catch (error) { results.push({ name, ok: false, detail: error instanceof Error ? error.message : String(error) }); }
  };
  const expect = (condition: unknown, message: string) => { if (!condition) throw new Error(message); };

  /** A did:vh identity that names `host` (its did:web DID) in alsoKnownAs. */
  const identity = async (host: string, names: string[] = [host]) => {
    const [k0, k1, k2] = [key(), key(), key()];
    const created = await createVhLog({
      signer: k0, updateKeys: [k0.multikey], nextKeyHashes: [keyHash(k1.multikey)],
      document: did => ({
        "@context": ["https://www.w3.org/ns/did/v1"], id: did, alsoKnownAs: names.map(name => didWebFor(`https://${name}`)),
        verificationMethod: [{ id: `${did}#k`, type: "Multikey", controller: did, publicKeyMultibase: k0.multikey }], authentication: [`${did}#k`],
      }),
    });
    return { ...created, host, k0, k1, k2 };
  };
  const logUrl = (host: string) => `https://${host}/.well-known/did.jsonl`;
  const webUrl = (host: string) => `https://${host}/.well-known/did.json`;
  const put = (host: string, log: VhLogEntry[]) => target.fetch(logUrl(host), { method: "PUT", headers: { "content-type": "text/jsonl" }, body: serializeVhLog(log) });
  const status = async (url: string, init?: RequestInit) => (await target.fetch(url, init)).status;
  const scidUrl = (host: string, scid: string) => `https://${host}/log?scid=${scid}`;
  const refused = (code: number) => code >= 400 && code < 500;

  const host = target.newLocation();
  const alice = await identity(host);
  let log = alice.log;
  const scid = alice.did.slice("did:vh:".length);

  await check("V1. PUT of a valid did:vh log that names this location creates it (201) and GET returns the same bytes", async () => {
    const response = await put(host, log);
    expect(response.status === 201, `expected 201, got ${response.status}: ${await response.text()}`);
    expect(await (await target.fetch(logUrl(host))).text() === serializeVhLog(log), "the published log differs");
  });

  await check("V2. did.json is the did:web document derived from the latest did:vh document", async () => {
    const response = await target.fetch(webUrl(host));
    expect(response.status === 200, `expected 200, got ${response.status}`);
    const verdict = checkDidWebShadow(log.at(-1)!.state, didWebFor(`https://${host}`), await response.json());
    expect(verdict.ok, verdict.ok ? "" : verdict.reason);
  });

  await check("V3. GET /log?scid=<SCID> returns the log from any host name, readable from any origin", async () => {
    for (const where of [host, target.newLocation()]) {
      const response = await target.fetch(scidUrl(where, scid), { headers: { origin: "https://wallet.example" } });
      expect(response.status === 200, `${where}: expected 200, got ${response.status}`);
      expect(await response.text() === serializeVhLog(log), `${where}: the log differs`);
      const allow = response.headers.get("access-control-allow-origin");
      expect(allow === "*" || allow === "https://wallet.example", `got ${allow}`);
    }
    expect(await status(scidUrl(host, "1".repeat(46))) === 404, "an unknown SCID must be 404");
    expect(refused(await status(`https://${host}/log?scid=not-a-scid`)), "a malformed SCID must be 4xx");
  });

  await check("V4. POST of a valid next entry appends it (204) and did.json follows it", async () => {
    const next = await updateVhLog({
      log, signer: alice.k1, now: Date.now() + 2000,
      document: { ...log[0]!.state, service: [{ id: `${alice.did}#s`, type: "S", serviceEndpoint: "https://s.example" }] },
      parameters: { updateKeys: [alice.k1.multikey], nextKeyHashes: [keyHash(alice.k2.multikey)] },
    });
    const post = await target.fetch(logUrl(host), { method: "POST", headers: { "content-type": "text/jsonl" }, body: `${JSON.stringify(next.log.at(-1))}\n` });
    expect(post.status === 204, `expected 204, got ${post.status}: ${await post.text()}`);
    log = next.log;
    const document = await (await target.fetch(webUrl(host))).json();
    expect(document.service?.[0]?.serviceEndpoint === "https://s.example", "did.json did not follow the update");
  });

  await check("V5. a log whose current document does not name this location is refused (4xx), and nothing is stored", async () => {
    const elsewhere = target.newLocation();
    const stranger = await identity(target.newLocation()); // names another location
    expect(refused((await put(elsewhere, stranger.log)).status), "expected 4xx");
    expect(await status(logUrl(elsewhere)) === 404, "nothing may be stored");
    expect(await status(scidUrl(elsewhere, stranger.did.slice(7))) === 404, "nothing may be indexed");
  });

  await check("V6. an update that stops naming the location, an unsigned genesis and a tampered entry are refused (4xx), log intact", async () => {
    const unnamed = await updateVhLog({ log, signer: alice.k2, now: Date.now() + 4000, document: { ...log.at(-1)!.state, alsoKnownAs: [] }, parameters: { updateKeys: [alice.k2.multikey], nextKeyHashes: [] } });
    expect(refused((await target.fetch(logUrl(host), { method: "POST", headers: { "content-type": "text/jsonl" }, body: `${JSON.stringify(unnamed.log.at(-1))}\n` })).status), "an update that stops naming the location was accepted");
    const eveHost = target.newLocation();
    const eve = await identity(eveHost);
    expect(refused((await put(eveHost, [{ ...eve.log[0]!, proof: [] }])).status), "an unsigned genesis was accepted");
    expect(await status(logUrl(eveHost)) === 404, "nothing may be stored");
    const tampered = structuredClone(log.at(-1)!);
    tampered.state = { ...tampered.state, name: "tampered" };
    expect(refused((await target.fetch(logUrl(host), { method: "POST", headers: { "content-type": "text/jsonl" }, body: `${JSON.stringify(tampered)}\n` })).status), "a tampered entry was accepted");
    expect(await (await target.fetch(logUrl(host))).text() === serializeVhLog(log), "the published log changed");
  });

  await check("V7. a SCID is published under one location only", async () => {
    const other = target.newLocation();
    const both = await updateVhLog({
      log, signer: alice.k2, now: Date.now() + 6000,
      document: { ...log.at(-1)!.state, alsoKnownAs: [didWebFor(`https://${host}`), didWebFor(`https://${other}`)] },
      parameters: { updateKeys: [alice.k2.multikey], nextKeyHashes: [] },
    });
    expect(refused((await put(other, both.log)).status), "the same SCID was accepted at a second location");
    expect(await status(logUrl(other)) === 404, "nothing may be stored");
  });

  await check("V8. a did:vh log is not replaced by another log: PUT must keep the published log as a prefix", async () => {
    const other = await identity(host);
    expect(refused((await put(host, other.log)).status), "expected 4xx");
    expect(await (await target.fetch(logUrl(host))).text() === serializeVhLog(log), "the published log changed");
  });

  await check("V9. deactivating removes did.json (404); the log, with its last entry, stays readable", async () => {
    const hostD = target.newLocation();
    const bob = await identity(hostD);
    expect((await put(hostD, bob.log)).status === 201, "could not publish");
    const done = await deactivateVhLog({ log: bob.log, signer: bob.k1, now: Date.now() + 2000 });
    const post = await target.fetch(logUrl(hostD), { method: "POST", headers: { "content-type": "text/jsonl" }, body: `${JSON.stringify(done.log.at(-1))}\n` });
    expect(post.status === 204, `expected 204, got ${post.status}: ${await post.text()}`);
    expect(await status(webUrl(hostD)) === 404, "did.json must be gone");
    expect(await status(scidUrl(hostD, bob.did.slice(7))) === 200, "the deactivated log must stay readable");
  });

  await check("V10. DELETE signed by a current update key takes the log, did.json and the SCID down (204); the location is free again", async () => {
    const request = async (signer: Ed25519Key) => {
      const document = { did: alice.did };
      const proof = await createDataIntegrityProof(document, { privateKey: signer.privateKey, verificationMethod: `did:key:${signer.multikey}#${signer.multikey}`, proofPurpose: "assertionMethod", created: new Date().toISOString() });
      return JSON.stringify({ ...document, proof });
    };
    expect(refused(await status(logUrl(host), { method: "DELETE", headers: { "content-type": "application/json" }, body: await request(key()) })), "a DELETE signed by a stranger was accepted");
    const response = await target.fetch(logUrl(host), { method: "DELETE", headers: { "content-type": "application/json" }, body: await request(alice.k1) });
    expect(response.status === 204, `expected 204, got ${response.status}: ${await response.text()}`);
    expect(await status(logUrl(host)) === 404 && await status(webUrl(host)) === 404, "the log or did.json is still readable");
    expect(await status(scidUrl(host, scid)) === 404, "the SCID must no longer be found");
    expect((await put(host, log)).status === 201, "the location must be free again");
    // best-effort cleanup, so repeated runs against a real server stay tidy
    await target.fetch(logUrl(host), { method: "DELETE", headers: { "content-type": "application/json" }, body: await request(alice.k1) }).catch(() => undefined);
  });

  return results;
}
