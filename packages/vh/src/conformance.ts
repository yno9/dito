/**
 * Executable form of SPEC-vh-hosting.md: black-box checks a server must pass to
 * interoperate with any conforming client. It only speaks HTTP and builds logs
 * with this package, so it runs against did.md's server or a third party's alike.
 */
import { createDataIntegrityProof } from "./proof.ts";
import { keyFromPrivateKey, type Ed25519Key } from "./signer.ts";
import { createVhLog, deactivateVhLog, updateVhLog } from "./create.ts";
import { checkDidWebShadow, didWebFor } from "./didweb.ts";
import { keyHash } from "./hash.ts";
import { serializeVhLog, type VhLogEntry } from "./log.ts";

const key = () => keyFromPrivateKey(crypto.getRandomValues(new Uint8Array(32)));

export type ConformanceTarget = {
  /** A fresh, unused location (DNS name) the server is willing to host, e.g. `conf-1a2b.did.md`. */
  newLocation(): string;
  /** Sends requests to the server under test (may rewrite the URL / Host header). */
  fetch: typeof fetch;
};

export type ConformanceResult = { name: string; ok: boolean; detail?: string; optional?: boolean };

/** Human-readable report; returns whether every non-optional check passed. */
export function formatReport(results: ConformanceResult[]): { text: string; ok: boolean } {
  const lines = results.map(r => `${r.ok ? "PASS" : r.optional ? "warn" : "FAIL"}  ${r.name}${r.ok || !r.detail ? "" : `\n      ${r.detail}`}`);
  const failed = results.filter(r => !r.ok && !r.optional).length;
  lines.push("", failed ? `${failed} required check(s) failed` : "all required checks passed");
  return { text: lines.join("\n"), ok: failed === 0 };
}

/** A disconnect request for `did`, signed by `signer`. */
async function deleteBody(did: string, signer: Ed25519Key): Promise<string> {
  const document = { did };
  const proof = await createDataIntegrityProof(document, { privateKey: signer.privateKey, verificationMethod: `did:key:${signer.multikey}#${signer.multikey}`, proofPurpose: "assertionMethod", created: new Date().toISOString() });
  return JSON.stringify({ ...document, proof });
}

export async function runVhConformance(target: ConformanceTarget): Promise<ConformanceResult[]> {
  const results: ConformanceResult[] = [];
  const check = async (name: string, fn: () => Promise<void>, optional = false) => {
    try { await fn(); results.push({ name, ok: true, optional }); }
    catch (error) { results.push({ name, ok: false, optional, detail: error instanceof Error ? error.message : String(error) }); }
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

  await check("V0. capability document (optional): valid when present", async () => {
    const response = await target.fetch(`https://${host}/.well-known/did-hosting.json`);
    if (!response.ok) return;
    const caps = await response.json() as { protocol?: unknown };
    expect(typeof caps.protocol === "string" && caps.protocol.startsWith("vh-hosting/"), "protocol must be vh-hosting/<n>");
  }, true);

  await check("V0. GET of an unpublished location is 404", async () => {
    expect(await status(logUrl(host)) === 404, "expected 404");
  });

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

  await check("V7. a SCID is published under one location: another continuation of its log at a second location is refused; a log that extends the published one (a move) takes it over", async () => {
    const from = target.newLocation(), to = target.newLocation();
    const carol = await identity(from);
    expect((await put(from, carol.log)).status === 201, "could not publish");
    const held = await updateVhLog({
      log: carol.log, signer: carol.k1, now: Date.now() + 2000,
      document: { ...carol.log[0]!.state, service: [{ id: "#s", type: "S", serviceEndpoint: "https://s.example" }] },
      parameters: { updateKeys: [carol.k1.multikey], nextKeyHashes: [keyHash(carol.k2.multikey)] },
    });
    const posted = await target.fetch(logUrl(from), { method: "POST", headers: { "content-type": "text/jsonl" }, body: `${JSON.stringify(held.log.at(-1))}\n` });
    expect(posted.status === 204, `expected 204, got ${posted.status}: ${await posted.text()}`);
    // The same first entry, another second entry that names the other location: valid, but it does not extend what the host holds.
    const fork = await updateVhLog({
      log: carol.log, signer: carol.k1, now: Date.now() + 2000,
      document: { ...carol.log[0]!.state, alsoKnownAs: [didWebFor(`https://${to}`)] },
      parameters: { updateKeys: [carol.k1.multikey], nextKeyHashes: [keyHash(carol.k2.multikey)] },
    });
    expect(refused((await put(to, fork.log)).status), "another continuation of the log was accepted at a second location");
    expect(await status(logUrl(to)) === 404, "nothing may be stored");
    // The move: the published log plus one entry that names the new location instead.
    const moved = await updateVhLog({
      log: held.log, signer: carol.k2, now: Date.now() + 4000,
      document: { ...held.log.at(-1)!.state, alsoKnownAs: [didWebFor(`https://${to}`)] },
      parameters: { updateKeys: [carol.k2.multikey], nextKeyHashes: [] },
    });
    const response = await put(to, moved.log);
    expect(response.status === 201, `expected 201, got ${response.status}: ${await response.text()}`);
    const scidOfCarol = carol.did.slice("did:vh:".length);
    expect(await (await target.fetch(scidUrl(to, scidOfCarol))).text() === serializeVhLog(moved.log), "the SCID must now find the moved log");
    // Taking the old copy down (signed by a key of the log it holds) leaves the SCID with the new location.
    const gone = await target.fetch(logUrl(from), { method: "DELETE", headers: { "content-type": "application/json" }, body: await deleteBody(carol.did, carol.k1) });
    expect(gone.status === 204, `expected 204, got ${gone.status}: ${await gone.text()}`);
    expect(await (await target.fetch(scidUrl(to, scidOfCarol))).text() === serializeVhLog(moved.log), "taking the old copy down must not unindex the new one");
    await target.fetch(logUrl(to), { method: "DELETE", headers: { "content-type": "application/json" }, body: await deleteBody(carol.did, carol.k2) }).catch(() => undefined);
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
    const request = (signer: Ed25519Key) => deleteBody(alice.did, signer);
    expect(refused(await status(logUrl(host), { method: "DELETE", headers: { "content-type": "application/json" }, body: await request(key()) })), "a DELETE signed by a stranger was accepted");
    const response = await target.fetch(logUrl(host), { method: "DELETE", headers: { "content-type": "application/json" }, body: await request(alice.k1) });
    expect(response.status === 204, `expected 204, got ${response.status}: ${await response.text()}`);
    expect(await status(logUrl(host)) === 404 && await status(webUrl(host)) === 404, "the log or did.json is still readable");
    expect(await status(scidUrl(host, scid)) === 404, "the SCID must no longer be found");
    expect((await put(host, log)).status === 201, "the location must be free again");
    // best-effort cleanup, so repeated runs against a real server stay tidy
    await target.fetch(logUrl(host), { method: "DELETE", headers: { "content-type": "application/json" }, body: await request(alice.k1) }).catch(() => undefined);
  });

  await check("V11. preflight allows PUT/POST/DELETE and content-type from any origin", async () => {
    const response = await target.fetch(logUrl(host), { method: "OPTIONS", headers: { origin: "https://wallet.example", "access-control-request-method": "PUT", "access-control-request-headers": "content-type" } });
    expect(response.status < 300, `expected 2xx, got ${response.status}`);
    const methods = (response.headers.get("access-control-allow-methods") ?? "").toUpperCase();
    for (const method of ["PUT", "POST", "DELETE"]) expect(methods.includes(method), `allow-methods lacks ${method}: ${methods}`);
    expect((response.headers.get("access-control-allow-headers") ?? "").toLowerCase().includes("content-type"), "allow-headers lacks content-type");
    const allow = response.headers.get("access-control-allow-origin");
    expect(allow === "*" || allow === "https://wallet.example", `got ${allow}`);
  });

  return results;
}
