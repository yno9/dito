import { expect, test } from "vitest";
import {
  ForkedLogError, InMemoryVersionMemory, StaleLogError, checkAndRemember, createVhLog, keyFromPrivateKey, keyHash,
  latestVersion, resolveVhFromWatchers, resolveVhLog, serializeVhLog, standingOf, updateVhLog, versionNumberOf,
} from "../packages/vh/src/index.ts";

const key = () => keyFromPrivateKey(crypto.getRandomValues(new Uint8Array(32)));

/** A log of three entries, plus the two different fourth entries that fork it. */
async function history() {
  const keys = [key(), key(), key(), key(), key()];
  const created = await createVhLog({
    signer: keys[0]!, updateKeys: [keys[0]!.multikey], nextKeyHashes: [keyHash(keys[1]!.multikey)],
    document: did => ({ "@context": ["https://www.w3.org/ns/did/v1"], id: did, verificationMethod: [{ id: `${did}#k`, type: "Multikey", controller: did, publicKeyMultibase: keys[0]!.multikey }], authentication: [`${did}#k`] }),
  });
  let clock = Date.now() + 1000;
  const rotate = async (log: typeof created.log, from: number, nextTo: number, service?: string) => {
    clock += 1000;
    return updateVhLog({
      log, signer: keys[from]!, now: clock, document: { ...log.at(-1)!.state, ...(service ? { service: [{ id: `${created.did}#a`, type: "A", serviceEndpoint: service }] } : {}) },
      parameters: { updateKeys: [keys[from]!.multikey], nextKeyHashes: [keyHash(keys[nextTo]!.multikey)] },
    });
  };
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

function watcherOf(logs: Record<string, string>): typeof fetch {
  return (async (url: string | URL) => {
    const body = logs[new URL(String(url)).searchParams.get("scid") ?? ""];
    return body === undefined ? new Response("", { status: 404 }) : new Response(body, { status: 200 });
  }) as typeof fetch;
}

const scidOf = (did: string) => did.slice("did:vh:".length);

test("resolveVhFromWatchers with a memory accepts the growing log and refuses an old copy served later", async () => {
  const { did, two, three } = await history();
  const memory = new InMemoryVersionMemory();
  const sources = (log: typeof two) => ({ watchers: ["https://w.example"], fetch: watcherOf({ [scidOf(did)]: serializeVhLog(log) }), memory });
  await resolveVhFromWatchers(did, sources(two));
  await resolveVhFromWatchers(did, sources(three));
  await expect(resolveVhFromWatchers(did, sources(two))).rejects.toThrow(StaleLogError);
});

test("resolveVhFromWatchers with a memory refuses the other continuation of a log it accepted", async () => {
  const { did, forkA, forkB } = await history();
  const memory = new InMemoryVersionMemory();
  await resolveVhFromWatchers(did, { watchers: ["https://w.example"], fetch: watcherOf({ [scidOf(did)]: serializeVhLog(forkA) }), memory });
  await expect(resolveVhFromWatchers(did, { watchers: ["https://w.example"], fetch: watcherOf({ [scidOf(did)]: serializeVhLog(forkB) }), memory })).rejects.toThrow(ForkedLogError);
});

test("without a memory, resolution behaves as before (any valid log is accepted)", async () => {
  const { did, two, three } = await history();
  await resolveVhFromWatchers(did, { watchers: ["https://w.example"], fetch: watcherOf({ [scidOf(did)]: serializeVhLog(three) }) });
  await resolveVhFromWatchers(did, { watchers: ["https://w.example"], fetch: watcherOf({ [scidOf(did)]: serializeVhLog(two) }) });
});

test("a log is remembered only after it verifies: an invalid log leaves the memory untouched", async () => {
  const { did, two, three } = await history();
  const memory = new InMemoryVersionMemory();
  await resolveVhLog(did, two, { memory });
  const broken = structuredClone(three);
  broken[2]!.state = { ...broken[2]!.state, service: [{ id: "#x", type: "X", serviceEndpoint: "https://evil.example" }] };
  await expect(resolveVhLog(did, broken, { memory })).rejects.toThrow();
  expect(memory.get(`did:vh:${scidOf(did)}`)).toEqual(latestVersion(two));
});
