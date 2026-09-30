/**
 * Executable form of SPEC-webvh-hosting.md: black-box checks a server must
 * pass to interoperate with any conforming client. It only speaks HTTP and
 * builds logs with didwebvh-ts, so it runs against did.md's server or a third
 * party's alike.
 */
import { createLog, updateLog, serializeLog, nextKeyHash, type DIDLog } from "./log.ts";
import { Ed25519Signer, keyFromPrivateKey, type Ed25519Key } from "./signer.ts";
import { WebvhHostingClient } from "./hosting.ts";
import { createDataIntegrityProof } from "./proof.ts";
import { didToLogUrl } from "./url.ts";

export type ConformanceTarget = {
  /** A fresh, unused location (DNS name) the server is willing to host, e.g. `conf-1a2b.did.md`. */
  newLocation(): string;
  /** Sends requests to the server under test (may rewrite the URL / Host header). */
  fetch: typeof fetch;
};

export type ConformanceResult = { name: string; ok: boolean; detail?: string; optional?: boolean };

const key = () => keyFromPrivateKey(crypto.getRandomValues(new Uint8Array(32)));

type Identity = { did: string; log: DIDLog; keys: Ed25519Key[]; update(): Promise<DIDLog> };

async function newIdentity(host: string): Promise<Identity> {
  const keys = [key(), key(), key()];
  const created = await createLog({
    domain: host, signer: new Ed25519Signer(keys[0]!), updateKeys: [keys[0]!.multikey], nextKeyHashes: [await nextKeyHash(keys[1]!.multikey)],
    verificationMethods: [{ id: "#k", type: "Multikey", publicKeyMultibase: keys[0]!.multikey }], authentication: ["#k"],
  });
  const identity: Identity = {
    did: created.did, log: created.log, keys,
    async update() {
      // rotate: signed by keys[1], committing to keys[2]
      const next = await updateLog({ log: identity.log, signer: new Ed25519Signer(keys[1]!), updateKeys: [keys[1]!.multikey], nextKeyHashes: [await nextKeyHash(keys[2]!.multikey)] });
      return next.log;
    },
  };
  return identity;
}

/** A delete request, optionally signed by the wrong key or backdated. */
async function deleteRequest(did: string, signer: Ed25519Key, created = new Date().toISOString()) {
  const document = { did };
  const proof = await createDataIntegrityProof(document, {
    privateKey: signer.privateKey, verificationMethod: `did:key:${signer.multikey}#${signer.multikey}`, proofPurpose: "assertionMethod", created,
  });
  return JSON.stringify({ ...document, proof });
}

export async function runConformance(target: ConformanceTarget): Promise<ConformanceResult[]> {
  const results: ConformanceResult[] = [];
  const client = new WebvhHostingClient({ fetch: target.fetch });
  const check = async (name: string, fn: () => Promise<void>, optional = false) => {
    try { await fn(); results.push({ name, ok: true, optional }); }
    catch (error) { results.push({ name, ok: false, optional, detail: error instanceof Error ? error.message : String(error) }); }
  };
  const expect = (condition: unknown, message: string) => { if (!condition) throw new Error(message); };
  const raw = (did: string, init?: RequestInit) => target.fetch(didToLogUrl(did), init);
  const status = async (did: string, init: RequestInit) => (await raw(did, init)).status;
  const logIntact = async (did: string, expected: DIDLog) => expect((await client.read(did)) === serializeLog(expected), "the published log changed");

  const host = target.newLocation();
  const alice = await newIdentity(host);
  const aliceText = serializeLog(alice.log);

  await check("capability document (optional): valid when present", async () => {
    const caps = await client.capabilities(host);
    if (caps) expect(caps.protocol.startsWith("webvh-hosting/"), "protocol must be webvh-hosting/<n>");
  }, true);

  await check("2. GET of an unpublished location is 404", async () => {
    expect(await status(alice.did, {}) === 404, "expected 404");
  });

  await check("3.1 PUT of a valid genesis log creates it (201) and GET returns the same bytes", async () => {
    const put = await raw(alice.did, { method: "PUT", headers: { "content-type": "text/jsonl" }, body: aliceText });
    expect(put.status === 201, `expected 201, got ${put.status}: ${await put.text()}`);
    await logIntact(alice.did, alice.log);
  });

  await check("2. published log is readable cross-origin (Access-Control-Allow-Origin: *)", async () => {
    const response = await raw(alice.did, { headers: { origin: "https://wallet.example" } });
    const allow = response.headers.get("access-control-allow-origin");
    expect(allow === "*" || allow === "https://wallet.example", `got ${allow}`);
  });

  await check("3.1 PUT of the identical log again replaces it (204)", async () => {
    const status_ = await status(alice.did, { method: "PUT", headers: { "content-type": "text/jsonl" }, body: aliceText });
    expect(status_ === 204, `expected 204, got ${status_}`);
  });

  await check("3.2 POST of a valid next entry appends it (204)", async () => {
    const next = await alice.update();
    const entry = `${JSON.stringify(next.at(-1))}\n`;
    const post = await raw(alice.did, { method: "POST", headers: { "content-type": "text/jsonl" }, body: entry });
    expect(post.status === 204, `expected 204, got ${post.status}: ${await post.text()}`);
    alice.log = next;
    await logIntact(alice.did, alice.log);
  });

  await check("3.1 PUT that does not preserve the existing log is refused (4xx) and changes nothing", async () => {
    const other = await newIdentity(host); // same location, different SCID
    const s = await status(alice.did, { method: "PUT", headers: { "content-type": "text/jsonl" }, body: serializeLog(other.log) });
    expect(s >= 400 && s < 500, `expected 4xx, got ${s}`);
    await logIntact(alice.did, alice.log);
  });

  await check("3.2 POST of an entry with a tampered document is refused (4xx) and changes nothing", async () => {
    const good = await alice.update().catch(() => undefined); // not committed; only used to build a bad entry
    const badEntry = { ...(good?.at(-1) ?? alice.log.at(-1)!), state: { ...alice.log.at(-1)!.state, name: "tampered" } };
    const s = await status(alice.did, { method: "POST", headers: { "content-type": "text/jsonl" }, body: `${JSON.stringify(badEntry)}\n` });
    expect(s >= 400 && s < 500, `expected 4xx, got ${s}`);
    await logIntact(alice.did, alice.log);
  });

  await check("3.1 an unsigned genesis (proof: []) is refused (4xx)", async () => {
    const eve = await newIdentity(target.newLocation());
    const unsigned = [{ ...eve.log[0]!, proof: [] }];
    const s = await status(eve.did, { method: "PUT", headers: { "content-type": "text/jsonl" }, body: serializeLog(unsigned as DIDLog) });
    expect(s >= 400 && s < 500, `expected 4xx, got ${s}`);
    expect(await status(eve.did, {}) === 404, "nothing may be stored");
  });

  await check("3.1 a log whose current DID designates another location is refused (4xx)", async () => {
    const elsewhere = await newIdentity(target.newLocation());
    const here = target.newLocation();
    const at = await newIdentity(here); // location `here` is free; upload someone else's log there
    const s = await target.fetch(didToLogUrl(at.did), { method: "PUT", headers: { "content-type": "text/jsonl" }, body: serializeLog(elsewhere.log) }).then(r => r.status);
    expect(s >= 400 && s < 500, `expected 4xx, got ${s}`);
    expect(await status(at.did, {}) === 404, "nothing may be stored");
  });

  await check("3.4 DELETE signed by a key that is not a current update key is refused (4xx), log intact", async () => {
    const s = await status(alice.did, { method: "DELETE", headers: { "content-type": "application/json" }, body: await deleteRequest(alice.did, key()) });
    expect(s >= 400 && s < 500, `expected 4xx, got ${s}`);
    await logIntact(alice.did, alice.log);
  });

  await check("3.4 DELETE with a proof older than 5 minutes is refused (4xx), log intact", async () => {
    const stale = new Date(Date.now() - 10 * 60_000).toISOString();
    const s = await status(alice.did, { method: "DELETE", headers: { "content-type": "application/json" }, body: await deleteRequest(alice.did, alice.keys[1]!, stale) });
    expect(s >= 400 && s < 500, `expected 4xx, got ${s}`);
    await logIntact(alice.did, alice.log);
  });

  await check("3.4 DELETE signed by a current update key removes the log (204); then GET is 404 and DELETE is 404", async () => {
    expect(await client.remove(alice.did, alice.keys[1]!), "expected the log to be removed");
    expect(await status(alice.did, {}) === 404, "log still readable");
    expect(await client.remove(alice.did, alice.keys[1]!) === false, "second DELETE should be 404");
  });

  await check("6. after DELETE the location is free again: the same log can be republished (201)", async () => {
    const put = await client.publish(alice.did, serializeLog(alice.log));
    expect(put.created, "expected 201");
  });

  await check("3.3 PUT of a malformed did-witness.json is refused (4xx)", async () => {
    const s = await status(alice.did, { method: "PUT", headers: { "content-type": "application/json" }, body: "{not json" });
    void s;
    const response = await target.fetch(`${client.baseUrl(alice.did)}did-witness.json`, { method: "PUT", headers: { "content-type": "application/json" }, body: "{not json" });
    expect(response.status >= 400 && response.status < 500, `expected 4xx, got ${response.status}`);
  }, true);

  await check("4. preflight allows PUT/POST/DELETE and content-type from any origin", async () => {
    const response = await raw(alice.did, { method: "OPTIONS", headers: { origin: "https://wallet.example", "access-control-request-method": "PUT", "access-control-request-headers": "content-type" } });
    expect(response.status < 300, `expected 2xx, got ${response.status}`);
    const methods = (response.headers.get("access-control-allow-methods") ?? "").toUpperCase();
    for (const method of ["PUT", "POST", "DELETE"]) expect(methods.includes(method), `allow-methods lacks ${method}: ${methods}`);
    expect((response.headers.get("access-control-allow-headers") ?? "").toLowerCase().includes("content-type"), "allow-headers lacks content-type");
    const allow = response.headers.get("access-control-allow-origin");
    expect(allow === "*" || allow === "https://wallet.example", `got ${allow}`);
  });

  // cleanup: best-effort, so repeated runs against a real server stay tidy
  await client.remove(alice.did, alice.keys[1]!).catch(() => undefined);
  return results;
}

/** Human-readable report; returns whether every non-optional check passed. */
export function formatReport(results: ConformanceResult[]): { text: string; ok: boolean } {
  const lines = results.map(r => `${r.ok ? "PASS" : r.optional ? "warn" : "FAIL"}  ${r.name}${r.ok || !r.detail ? "" : `\n      ${r.detail}`}`);
  const failed = results.filter(r => !r.ok && !r.optional).length;
  lines.push("", failed ? `${failed} required check(s) failed` : "all required checks passed");
  return { text: lines.join("\n"), ok: failed === 0 };
}
