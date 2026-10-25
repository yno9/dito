import { expect, test } from "vitest";
import { keyFromPrivateKey } from "../packages/webvh/src/index.ts";
import {
  VhResolutionError, checkDidWebShadow, createVhLog, deriveDidWebDocument, didWebFor, fetchVhLog, logUrlOf, parseWebLocation, resolveVhLog,
  serializeVhLog,
} from "../packages/vh/src/index.ts";

const key = () => keyFromPrivateKey(crypto.getRandomValues(new Uint8Array(32)));

// ---- the specification's examples ---------------------------------------------------------------------------------

test("web location → log URL, exactly as didvh-spec lists them", () => {
  expect(logUrlOf("https://example.com")).toBe("https://example.com/.well-known/did.jsonl");
  expect(logUrlOf("https://example.com/")).toBe("https://example.com/.well-known/did.jsonl");
  expect(logUrlOf("https://example.com/dids/issuer")).toBe("https://example.com/dids/issuer/did.jsonl");
  expect(logUrlOf("https://example.com:3000/dids/issuer")).toBe("https://example.com:3000/dids/issuer/did.jsonl");
  expect(logUrlOf("https://example.com/users/{SCID}")).toBe("https://example.com/users/{SCID}/did.jsonl");
  expect(logUrlOf("http://localhost:8000/dids/issuer", { allowLoopback: true })).toBe("http://localhost:8000/dids/issuer/did.jsonl");
  expect(logUrlOf("https://ALICE.did.md")).toBe("https://alice.did.md/.well-known/did.jsonl");
});

test("an internationalised host is converted to its A-label form", () => {
  expect(parseWebLocation("https://bücher.example").host).toBe("xn--bcher-kva.example");
});

test("src refuses what a fetcher must not follow", () => {
  const bad = [
    "http://example.com", "ftp://example.com", "example.com", "//example.com", "https://", "https://user@example.com", "https://user:pw@example.com",
    "https://example.com?x=1", "https://example.com/#f", "https://example.com/a?x", "https://example.com:0", "https://example.com:70000",
    "https://127.0.0.1", "https://10.0.0.1/dids", "https://[::1]", "https://[2001:db8::1]", "https://2130706433", "https://0x7f.1", "https://localhost", "https://intranet",
    "https://example.com/a/../b", "https://example.com/a/./b", "https://example.com/%2e%2e/b", "https://example.com/a%2Fb", "https://example.com/a%5Cb",
    "https://example.com/a%00b", "https://example.com/a//b", "https://example.com/%20a", "https://example.com/a\\b", "https://exa mple.com",
  ];
  for (const src of bad) expect(() => parseWebLocation(src), src).toThrow(VhResolutionError);
  for (const src of bad) expect(() => parseWebLocation(src), src).toThrow(expect.objectContaining({ code: "invalidOptions" }));
});

test("http is for a loopback host in a local resolver, and only then", () => {
  expect(() => parseWebLocation("http://localhost:8000")).toThrow();
  expect(() => parseWebLocation("http://example.com", { allowLoopback: true })).toThrow();
  expect(() => parseWebLocation("http://10.0.0.1", { allowLoopback: true })).toThrow();
  for (const host of ["localhost", "127.0.0.1", "127.1.2.3", "[::1]"]) expect(parseWebLocation(`http://${host}:8000/x`, { allowLoopback: true }).origin).toBe(`http://${host}:8000`);
});

// ---- fetching ------------------------------------------------------------------------------------------------------

async function published() {
  const k0 = key();
  const created = await createVhLog({ signer: k0, updateKeys: [k0.multikey], document: did => ({ "@context": ["https://www.w3.org/ns/did/v1"], id: did }) });
  return { ...created, k0 };
}

test("fetchVhLog gets did.jsonl from the right URL with no redirects and no caches, and the log resolves", async () => {
  const { did, log } = await published();
  const seen: Array<{ url: string; init?: RequestInit }> = [];
  const fakeFetch = (async (url: string | URL, init?: RequestInit) => { seen.push({ url: String(url), init }); return new Response(serializeVhLog(log)); }) as typeof fetch;
  const fetched = await fetchVhLog("https://alice.did.md", { fetch: fakeFetch });
  expect(seen).toHaveLength(1);
  expect(seen[0]!.url).toBe("https://alice.did.md/.well-known/did.jsonl");
  expect(seen[0]!.init).toMatchObject({ redirect: "error", cache: "no-store" });
  expect((await resolveVhLog(did, fetched.log)).doc!.id).toBe(did);
});

test("fetchVhLog: a missing log is notFound, a server error is notFound, a transport error is notFound, junk is invalidLog", async () => {
  const respond = (response: () => Response | Promise<Response>) => ({ fetch: (async () => response()) as typeof fetch });
  await expect(fetchVhLog("https://a.example", respond(() => new Response("", { status: 404 })))).rejects.toMatchObject({ code: "notFound" });
  await expect(fetchVhLog("https://a.example", respond(() => new Response("", { status: 502 })))).rejects.toMatchObject({ code: "notFound" });
  await expect(fetchVhLog("https://a.example", respond(() => { throw new TypeError("redirect"); }))).rejects.toMatchObject({ code: "notFound" });
  await expect(fetchVhLog("https://a.example", respond(() => new Response("not json\n")))).rejects.toMatchObject({ code: "invalidLog" });
  await expect(fetchVhLog("https://a.example", respond(() => new Response("")))).rejects.toMatchObject({ code: "invalidLog" });
});

test("fetchVhLog bounds the body, by the declared length and by what arrives", async () => {
  const big = "x".repeat(2000);
  await expect(fetchVhLog("https://a.example", { maxBytes: 1000, fetch: (async () => new Response(big, { headers: { "content-length": "2000" } })) as typeof fetch })).rejects.toMatchObject({ code: "invalidLog" });
  await expect(fetchVhLog("https://a.example", { maxBytes: 1000, fetch: (async () => new Response(big)) as typeof fetch })).rejects.toMatchObject({ code: "invalidLog" });
});

test("fetchVhLog never reaches the network for a src that is refused", async () => {
  let called = false;
  const fakeFetch = (async () => { called = true; return new Response(""); }) as typeof fetch;
  await expect(fetchVhLog("https://127.0.0.1/x", { fetch: fakeFetch })).rejects.toThrow(VhResolutionError);
  expect(called).toBe(false);
});

// ---- the did:web shadow --------------------------------------------------------------------------------------------

test("didWebFor: did:web:<host>[%3A<port>][:<path>]", () => {
  expect(didWebFor("https://alice.did.md")).toBe("did:web:alice.did.md");
  expect(didWebFor("https://example.com:3000/dids/issuer")).toBe("did:web:example.com%3A3000:dids:issuer");
  expect(didWebFor("http://localhost:8000", { allowLoopback: true })).toBe("did:web:localhost%3A8000");
});

async function identityWithShadow() {
  const k0 = key();
  const webDid = "did:web:alice.did.md";
  const created = await createVhLog({
    signer: k0, updateKeys: [k0.multikey],
    document: did => ({
      "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"], id: did,
      alsoKnownAs: [webDid, `${did.replace("{SCID}", "{SCID}")}?src=https://alice.did.md`],
      controller: did,
      verificationMethod: [{ id: `${did}#k`, type: "Multikey", controller: did, publicKeyMultibase: k0.multikey }],
      authentication: [`${did}#k`], assertionMethod: ["#k"],
      service: [{ id: `${did}#wallet`, type: "SelfIssuedOPAuthorizationEndpoint", serviceEndpoint: "https://dito.did.md/authorize" }],
    }),
  });
  return { ...created, webDid, doc: created.log[0]!.state };
}

test("the did:web document is the did:vh document with the DID replaced and alsoKnownAs reduced to the did:vh DID", async () => {
  const { did, webDid, doc } = await identityWithShadow();
  const shadow = deriveDidWebDocument(doc, webDid);
  expect(shadow.id).toBe(webDid);
  expect(shadow.controller).toBe(webDid);
  expect(shadow.verificationMethod[0]).toMatchObject({ id: `${webDid}#k`, controller: webDid });
  expect(shadow.authentication).toEqual([`${webDid}#k`]);
  expect(shadow.assertionMethod).toEqual(["#k"]);
  expect(shadow.service[0].id).toBe(`${webDid}#wallet`);
  expect(shadow.service[0].serviceEndpoint).toBe("https://dito.did.md/authorize");
  expect(shadow.alsoKnownAs).toEqual([did]);
  expect(JSON.stringify(shadow)).not.toContain("?src=");
  // The original is untouched.
  expect(doc.id).toBe(did);
  expect(doc.alsoKnownAs).toHaveLength(2);
});

test("a did:web document is accepted only when it is exactly the derivation of the did:vh document that names it", async () => {
  const { did, webDid, doc } = await identityWithShadow();
  const shadow = deriveDidWebDocument(doc, webDid);
  expect(checkDidWebShadow(doc, webDid, shadow)).toEqual({ ok: true });
  expect(checkDidWebShadow(doc, webDid, JSON.parse(JSON.stringify(shadow)))).toEqual({ ok: true });

  const reason = (webDocument: unknown, document = doc, as = webDid) => (checkDidWebShadow(document, as, webDocument) as { reason: string }).reason;
  // A key the did:vh document does not hold.
  expect(reason({ ...shadow, verificationMethod: [{ ...shadow.verificationMethod[0], publicKeyMultibase: key().multikey }] })).toMatch(/not what the did:vh document derives/);
  // An extra service, an extra alias, a different id.
  expect(reason({ ...shadow, service: [...shadow.service, { id: "#x", type: "X", serviceEndpoint: "https://evil.example" }] })).toMatch(/not what/);
  expect(reason({ ...shadow, alsoKnownAs: [did, "https://evil.example"] })).toMatch(/not what/);
  expect(reason({ ...shadow, id: "did:web:evil.example" })).toMatch(/not what/);
  expect(reason({ ...shadow, alsoKnownAs: ["did:vh:" + "1".repeat(46)] })).toMatch(/not what/);
  // The did:vh document must name this did:web DID: a link in both directions.
  expect(reason(shadow, doc, "did:web:bob.did.md")).toMatch(/does not name did:web:bob.did.md/);
  expect(reason(shadow, { ...doc, alsoKnownAs: [] })).toMatch(/does not name/);
  expect(reason(null)).toMatch(/not an object/);
  expect(reason([])).toMatch(/not an object/);
});

test("deriving refuses a document that is not a did:vh document", () => {
  expect(() => deriveDidWebDocument({ id: "did:webvh:Qm:example.com" }, "did:web:example.com")).toThrow(/Not a did:vh/);
});
