import { expect, test } from "vitest";
import {
  Ed25519Signer, ForkedLogError, InMemoryVersionMemory, StaleLogError, checkAndRemember, createLog, fetchDidLog, keyFromPrivateKey,
  latestVersion, nextKeyHash, resolveDidWebvh, serializeLog, standingOf, updateLog, verifyDidLog, versionNumberOf,
} from "../packages/webvh/src/index.ts";

const key = () => keyFromPrivateKey(crypto.getRandomValues(new Uint8Array(32)));

/** A log of three entries, plus the two different fourth entries that fork it. */
async function history() {
  const keys = [key(), key(), key(), key(), key()];
  const signer = (index: number) => new Ed25519Signer(keys[index]!);
  const created = await createLog({
    domain: "example.com", signer: signer(0), updateKeys: [keys[0]!.multikey], nextKeyHashes: [await nextKeyHash(keys[1]!.multikey)],
    verificationMethods: [{ id: "#k", type: "Multikey", publicKeyMultibase: keys[0]!.multikey }], authentication: ["#k"],
  });
  const rotate = async (log: typeof created.log, from: number, nextTo: number, service?: string) => updateLog({
    log, signer: signer(from), updateKeys: [keys[from]!.multikey], nextKeyHashes: [await nextKeyHash(keys[nextTo]!.multikey)],
    ...(service ? { services: [{ id: "#a", type: "A", serviceEndpoint: service }] } : {}),
  });
  const second = await rotate(created.log, 1, 2);
  const third = await rotate(second.log, 2, 3);
  // Two different continuations of the same three entries (same pre-committed key 3, different content).
  const forkA = await rotate(third.log, 3, 4, "https://a.example");
  const forkB = await rotate(third.log, 3, 4, "https://b.example");
  return { did: created.did, one: created.log, two: second.log, three: third.log, forkA: forkA.log, forkB: forkB.log };
}

test("versionNumberOf reads the number and refuses a malformed versionId", () => {
  expect(versionNumberOf("12-QmAbc")).toBe(12);
  for (const bad of ["", "0-Qm", "x-Qm", "3", "-Qm"]) expect(() => versionNumberOf(bad)).toThrow();
});

test("standingOf: nothing known is new; the same log is same; a longer one extending it is newer", async () => {
  const { three, two } = await history();
  expect(standingOf(three)).toBe("new");
  expect(standingOf(three, latestVersion(three))).toBe("same");
  expect(standingOf(three, latestVersion(two))).toBe("newer");
});

test("standingOf refuses an older copy (stale) and another continuation (forked)", async () => {
  const { three, two, forkA, forkB } = await history();
  expect(() => standingOf(two, latestVersion(three))).toThrow(StaleLogError);
  expect(() => standingOf(forkB, latestVersion(forkA))).toThrow(ForkedLogError);
  expect(() => standingOf(forkA, latestVersion(forkB))).toThrow(ForkedLogError);
});

test("a fork is told apart from an old copy even when the forked log is longer", async () => {
  const { three, forkA, forkB } = await history();
  const known = latestVersion(forkA);
  expect(forkB.length).toBe(forkA.length);
  expect(() => standingOf(forkB, known)).toThrow(ForkedLogError);
  expect(standingOf(forkA, latestVersion(three))).toBe("newer");
});

test("checkAndRemember keeps the newest version and never moves back", async () => {
  const { one, two, three } = await history();
  const memory = new InMemoryVersionMemory();
  expect(await checkAndRemember(memory, "k", two)).toBe("new");
  expect(await checkAndRemember(memory, "k", three)).toBe("newer");
  expect(memory.get("k")).toEqual(latestVersion(three));
  await expect(checkAndRemember(memory, "k", one)).rejects.toThrow(StaleLogError);
  expect(memory.get("k")).toEqual(latestVersion(three));
  expect(await checkAndRemember(memory, "k", three)).toBe("same");
});

test("keys are separate: one identity's history does not constrain another", async () => {
  const { three } = await history();
  const other = await history();
  const memory = new InMemoryVersionMemory();
  await checkAndRemember(memory, "a", three);
  expect(await checkAndRemember(memory, "b", other.one)).toBe("new");
});

function hostOf(logs: Record<string, string>): typeof fetch {
  return (async (url: string | URL) => {
    const body = logs[String(url)];
    return body === undefined ? new Response("", { status: 404 }) : new Response(body, { status: 200 });
  }) as typeof fetch;
}

test("resolveDidWebvh with a memory accepts the growing log and refuses an old copy served later", async () => {
  const { did, two, three } = await history();
  const url = "https://example.com/.well-known/did.jsonl";
  const memory = new InMemoryVersionMemory();
  await resolveDidWebvh(did, { fetch: hostOf({ [url]: serializeLog(two) }), memory });
  await resolveDidWebvh(did, { fetch: hostOf({ [url]: serializeLog(three) }), memory });
  await expect(resolveDidWebvh(did, { fetch: hostOf({ [url]: serializeLog(two) }), memory })).rejects.toThrow(StaleLogError);
});

test("resolveDidWebvh with a memory refuses the other continuation of a log it accepted", async () => {
  const { did, forkA, forkB } = await history();
  const url = "https://example.com/.well-known/did.jsonl";
  const memory = new InMemoryVersionMemory();
  await resolveDidWebvh(did, { fetch: hostOf({ [url]: serializeLog(forkA) }), memory });
  await expect(resolveDidWebvh(did, { fetch: hostOf({ [url]: serializeLog(forkB) }), memory })).rejects.toThrow(ForkedLogError);
});

test("without a memory, resolveDidWebvh behaves as before (any valid log is accepted)", async () => {
  const { did, two, three } = await history();
  const url = "https://example.com/.well-known/did.jsonl";
  await resolveDidWebvh(did, { fetch: hostOf({ [url]: serializeLog(three) }) });
  await resolveDidWebvh(did, { fetch: hostOf({ [url]: serializeLog(two) }) });
});

test("a log is remembered only after it verifies: an invalid log leaves the memory untouched", async () => {
  const { did, two, three } = await history();
  const memory = new InMemoryVersionMemory();
  await verifyDidLog(did, { log: two }, { memory });
  const broken = structuredClone(three);
  broken[2]!.state = { ...broken[2]!.state, service: [{ id: "#x", type: "X", serviceEndpoint: "https://evil.example" }] };
  await expect(verifyDidLog(did, { log: broken }, { memory })).rejects.toThrow();
  expect(memory.get(`did:webvh:${did.split(":")[2]}`)).toEqual(latestVersion(two));
});

test("fetchDidLog only fetches: a log for another DID is returned, and verifyDidLog refuses it", async () => {
  const mine = await history();
  const theirs = await history();
  const url = "https://example.com/.well-known/did.jsonl";
  const fetched = await fetchDidLog(mine.did, { fetch: hostOf({ [url]: serializeLog(theirs.three) }) });
  expect(fetched.log).toHaveLength(3);
  await expect(verifyDidLog(mine.did, fetched)).rejects.toThrow(/expected DID/);
});
