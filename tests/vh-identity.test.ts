// Identity (packages/wallet/src/identity.ts) against did.md's host, through identityFetch with an in-memory store.
import { afterEach, expect, test } from "vitest";
import { checkDidWebShadow, locationsOf, parseVhLog, resolveVhLog, serializeVhLog } from "../packages/vh/src/index.ts";
import { Identity, locationFor } from "../packages/wallet/src/identity.ts";
import { MemoryStore, freshHost, resetHost, viaHost } from "./helpers/vh-host.ts";

let store: MemoryStore;
function host() { store = freshHost(); }
afterEach(() => resetHost());

const get = (url: string) => viaHost(url);

test("an identity can be created with no host: a valid did:vh log and nothing else", async () => {
  const { identity, mnemonic } = await Identity.create({ api: "https://dito.did.md/authorize", displayName: "Alice" });
  expect(mnemonic.split(" ")).toHaveLength(24);
  expect(identity.did).toMatch(/^did:vh:[1-9A-HJ-NP-Za-km-z]{46}$/);
  expect(identity.scid).toBe(identity.did.slice(7));
  expect(identity.isProvisional).toBe(true);
  expect(identity.locations).toEqual([]);
  expect(identity.entries).toHaveLength(1);
  expect(identity.state).toMatchObject({
    id: identity.did, name: "Alice", authentication: ["#pass-1"],
    verificationMethod: [{ id: "#pass-1", type: "Multikey", controller: identity.did }],
    service: [{ id: "#wallet", type: "SelfIssuedOPAuthorizationEndpoint", serviceEndpoint: "https://dito.did.md/authorize" }],
  });
  expect(identity.parameters).toMatchObject({ method: "did:vh:1.0", deactivated: false });
  expect(identity.parameters.nextKeyHashes).toHaveLength(1);
  await resolveVhLog(identity.did, [...identity.entries]);
  expect(await identity.isLive()).toBe(false);
  await expect(identity.publish()).rejects.toThrow(/no location/);
  await expect(identity.unpublish()).rejects.toThrow(/no location/);
});

test("open: the mnemonic and the log are the whole identity; another passphrase is refused", async () => {
  const { identity, mnemonic } = await Identity.create();
  const same = await Identity.open({ mnemonic, log: identity.logText() });
  expect(same.did).toBe(identity.did);
  expect(same.mnemonic).toBe(mnemonic);
  const other = await Identity.create();
  await expect(Identity.open({ mnemonic: other.mnemonic, log: identity.logText() })).rejects.toThrow(/genesis Root Key/);
  await expect(Identity.open({ log: identity.logText() })).rejects.toThrow(/mnemonic or master seed/);
  // A log that is not valid is refused before anything about keys is asked.
  const broken = parseVhLog(identity.logText());
  broken[0]!.state = { ...broken[0]!.state, name: "tampered" };
  await expect(Identity.open({ mnemonic, log: broken })).rejects.toThrow();
});

test("connect: one entry gives the identity a location and publishes the whole log there; the DID does not change", async () => {
  host();
  const { identity } = await Identity.create({ api: "https://dito.did.md/authorize", fetch: viaHost });
  const did = identity.did;
  const result = await identity.connect({ username: "alice" });
  expect(result).toMatchObject({ did, src: "https://alice.did.md", logUrl: "https://alice.did.md/.well-known/did.jsonl", verifiedLive: true });
  expect(identity.did).toBe(did);
  expect(identity.entries).toHaveLength(2);
  expect(identity.locations.map(location => location.src)).toEqual(["https://alice.did.md"]);
  expect(identity.state.alsoKnownAs).toEqual(["did:web:alice.did.md", `${did}?src=https://alice.did.md`]);
  expect(await identity.isLive()).toBe(true);
  expect(await (await get("https://alice.did.md/.well-known/did.jsonl")).text()).toBe(identity.logText());
  // The did:web document the host derived is exactly what a verifier derives from the did:vh document.
  const web = await (await get("https://alice.did.md/.well-known/did.json")).json();
  expect(web.id).toBe("did:web:alice.did.md");
  // Relative references stay relative; only the DID itself is replaced.
  expect(web.service[0]).toMatchObject({ id: "#wallet", serviceEndpoint: "https://dito.did.md/authorize" });
  expect(web.verificationMethod[0]).toMatchObject({ id: "#pass-1", controller: "did:web:alice.did.md" });
  expect(checkDidWebShadow(identity.state, "did:web:alice.did.md", web)).toEqual({ ok: true });
  expect(await identity.isLive()).toBe(true);
  await expect(identity.connect({ username: "alice" })).rejects.toThrow(/already at that location/);
});

test("born with a location: publish() is the first PUT, and the host accepts it as it is", async () => {
  host();
  const { identity } = await Identity.create({ location: { username: "bob" }, fetch: viaHost });
  expect(identity.entries).toHaveLength(1);
  expect(identity.isProvisional).toBe(false);
  expect(identity.state.alsoKnownAs).toEqual(["did:web:bob.did.md", `${identity.did}?src=https://bob.did.md`]);
  const result = await identity.publish();
  expect(result.verifiedLive).toBe(true);
  expect(await (await get(`https://bob.did.md/log?scid=${identity.scid}`)).text()).toBe(identity.logText());
});

test("publishUpdate and rotate: each is one pre-rotated entry, POSTed; the host and the identity agree after every one", async () => {
  host();
  const { identity, mnemonic } = await Identity.create({ fetch: viaHost });
  await identity.connect({ username: "alice" });
  const result = await identity.publishUpdate(state => { state.service = [...(state.service ?? []), { id: "#files", type: "relativeRef", serviceEndpoint: "https://alice.did.md/" }]; });
  expect(result?.verifiedLive).toBe(true);
  expect(identity.entries).toHaveLength(3);
  expect((await get("https://alice.did.md/.well-known/did.jsonl").then(r => r.text()))).toBe(identity.logText());
  const web = await (await get("https://alice.did.md/.well-known/did.json")).json();
  expect(web.service.find((s: any) => s.id === "#files")).toBeTruthy();
  for (let i = 0; i < 3; i += 1) expect((await identity.rotate())?.verifiedLive).toBe(true);
  expect(identity.entries).toHaveLength(6);
  // Permanent pre-rotation: exactly one commitment at every step, and the mnemonic still opens the identity.
  expect(identity.parameters.nextKeyHashes).toHaveLength(1);
  const reopened = await Identity.open({ mnemonic, log: identity.logText() });
  expect(reopened.entries).toHaveLength(6);
  await resolveVhLog(identity.did, [...identity.entries]);
});

test("an edit that stops naming the location is refused before anything is sent", async () => {
  host();
  const { identity } = await Identity.create({ fetch: viaHost });
  await identity.connect({ username: "alice" });
  const before = identity.logText();
  await expect(identity.publishUpdate(state => { state.alsoKnownAs = []; })).rejects.toThrow(/no longer names/);
  await expect(identity.publishUpdate(state => { state.alsoKnownAs = ["did:web:alice.did.md"]; })).rejects.toThrow(/no longer names/);
  expect(identity.logText()).toBe(before);
  expect(await (await get("https://alice.did.md/.well-known/did.jsonl")).text()).toBe(before);
});

test("without a location an update is local; a refused publication leaves local state where it was", async () => {
  host();
  const { identity } = await Identity.create({ fetch: viaHost });
  expect(await identity.publishUpdate(state => { state.name = "Alice"; })).toBeUndefined();
  expect(identity.entries).toHaveLength(2);
  // A host that has the name already: publication fails, and the identity is not advanced.
  const other = await Identity.create({ location: { username: "taken" }, fetch: viaHost });
  await other.identity.publish();
  const before = identity.logText();
  await expect(identity.connect({ username: "taken" })).rejects.toThrow();
  expect(identity.logText()).toBe(before);
  expect(identity.isProvisional).toBe(true);
});

test("a new device: the log is found by its SCID from any host name, or from its location, and the mnemonic opens it", async () => {
  host();
  const { identity, mnemonic } = await Identity.create({ fetch: viaHost });
  await identity.connect({ username: "alice" });
  await identity.rotate();
  const byScid = await Identity.fromSource({ mnemonic, watcher: "https://anywhere.did.md", scid: identity.scid, fetch: viaHost });
  expect(byScid.logText()).toBe(identity.logText());
  const bySrc = await Identity.fromSource({ mnemonic, src: "https://alice.did.md", fetch: viaHost });
  expect(bySrc.did).toBe(identity.did);
  // ...and it carries on from there: its update is accepted by the host.
  expect((await bySrc.rotate())?.verifiedLive).toBe(true);
  await expect(Identity.fromSource({ mnemonic, src: "https://nobody.did.md", fetch: viaHost })).rejects.toThrow(/Could not find/);
  await expect(Identity.fromSource({ mnemonic, fetch: viaHost })).rejects.toThrow(/src, or a watcher/);
  const wrong = await Identity.create();
  await expect(Identity.fromSource({ mnemonic: wrong.mnemonic, src: "https://alice.did.md", fetch: viaHost })).rejects.toThrow(/genesis Root Key/);
});

test("moving to another location keeps the DID, takes the old copy down, and the old name is free again", async () => {
  host();
  const { identity } = await Identity.create({ fetch: viaHost });
  await identity.connect({ username: "alice" });
  const did = identity.did;
  const moved = await identity.connect({ username: "alice2" });
  expect(moved.cleanupError).toBeUndefined();
  expect(identity.did).toBe(did);
  expect(identity.locations.map(location => location.src)).toEqual(["https://alice2.did.md"]);
  expect(identity.state.alsoKnownAs).toEqual(["did:web:alice2.did.md", `${did}?src=https://alice2.did.md`]);
  expect((await get("https://alice.did.md/.well-known/did.jsonl")).status).toBe(404);
  expect((await get("https://alice.did.md/.well-known/did.json")).status).toBe(404);
  expect(await (await get("https://alice2.did.md/.well-known/did.jsonl")).text()).toBe(identity.logText());
  expect(await (await get(`https://anywhere.did.md/log?scid=${identity.scid}`)).text()).toBe(identity.logText());
  expect(store.index.get(identity.scid)).toBe("alice2");
});

test("unpublish takes the log down from the host; the identity keeps its state and can publish again", async () => {
  host();
  const { identity } = await Identity.create({ fetch: viaHost });
  await identity.connect({ username: "alice" });
  await identity.unpublish();
  expect((await get("https://alice.did.md/.well-known/did.jsonl")).status).toBe(404);
  expect(await identity.isLive()).toBe(false);
  expect((await identity.publish()).verifiedLive).toBe(true);
});

test("connecting to a host that does not publish did:vh says so", async () => {
  host();
  // A host that serves no capability document (it does not speak the protocol).
  const elsewhere = (async (input: RequestInfo | URL, init?: RequestInit) => String(input).endsWith("/.well-known/did-hosting.json") ? new Response("", { status: 404 }) : viaHost(input, init)) as typeof fetch;
  const { identity } = await Identity.create({ fetch: elsewhere });
  await expect(identity.connect({ username: "alice" })).rejects.toThrow(/does not publish did:vh/);
  expect(identity.entries).toHaveLength(1);
});

test("the container carries the identity: seal, open, and the same log comes back", async () => {
  host();
  const { identity, mnemonic } = await Identity.create({ fetch: viaHost });
  await identity.connect({ username: "alice" });
  const { scid, jwe } = await identity.exportContainer();
  expect(scid).toBe(identity.scid);
  const opened = await Identity.fromContainer({ jwe, mnemonic });
  expect(opened.logText()).toBe(identity.logText());
  await expect(Identity.fromContainer({ jwe, mnemonic: (await Identity.create()).mnemonic })).rejects.toThrow();
});

test("locationFor builds the address and refuses a bad username", () => {
  expect(locationFor({ username: "alice" })).toBe("https://alice.did.md");
  expect(locationFor({ username: "alice", domain: "Example.COM" })).toBe("https://alice.example.com");
  expect(locationFor({ domain: "example.com" })).toBe("https://example.com");
  expect(() => locationFor({ username: "Al ice" })).toThrow(/Username/);
  expect(locationsOf("did:vh:x", { alsoKnownAs: [] })).toEqual([]);
  expect(serializeVhLog([])).toBe("\n");
});

test("moveToDomain (bring your own domain) names the host locally and derives the did:web document; nothing is published", async () => {
  host();
  const { identity, mnemonic } = await Identity.create({ fetch: viaHost });
  const result = await identity.moveToDomain("DigitalCommons.jp");
  expect(result.did).toBe(identity.did);
  expect(result).toMatchObject({ didWeb: "did:web:digitalcommons.jp", src: "https://digitalcommons.jp" });
  expect(identity.locations.map(location => location.src)).toEqual(["https://digitalcommons.jp"]);
  const web = JSON.parse(result.didJson);
  expect(web.id).toBe("did:web:digitalcommons.jp");
  expect(web.alsoKnownAs).toEqual([`${identity.did}?src=https://digitalcommons.jp`]);
  expect(checkDidWebShadow(identity.state, "did:web:digitalcommons.jp", web).ok).toBe(true);
  expect(store.files.size).toBe(0);
  await expect(identity.moveToDomain("not a host")).rejects.toThrow(/fully-qualified/);
  const reopened = await Identity.open({ mnemonic, log: identity.logText() });
  expect(reopened.locations).toHaveLength(1);

  // and a later move replaces the place, never adds a second
  const again = await identity.moveToDomain("example.org");
  expect(again.previousSrc).toBe("https://digitalcommons.jp");
  expect(identity.locations.map(location => location.src)).toEqual(["https://example.org"]);
});
