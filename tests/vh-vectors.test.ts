import { readFileSync } from "node:fs";
import { expect, test } from "vitest";
import { checkDidWebShadow, resolveVhLog, type VhLogEntry } from "../packages/vh/src/index.ts";
import { vectors } from "../packages/vh/vectors/generate.ts";

const FILE = new URL("../packages/vh/vectors/vectors.json", import.meta.url);
const shared = JSON.parse(readFileSync(FILE, "utf8")) as Awaited<ReturnType<typeof vectors>>;

test("vectors.json is what the generator produces (fixed keys, fixed times: nothing may drift)", async () => {
  expect(JSON.parse(JSON.stringify(await vectors()))).toEqual(shared);
});

test("the vectors cover valid and invalid logs, with the error codes a resolver reports", () => {
  expect(shared.vectors.filter(v => v.expect.ok).length).toBeGreaterThanOrEqual(6);
  expect(shared.vectors.filter(v => !v.expect.ok).length).toBeGreaterThanOrEqual(25);
  const codes = new Set(shared.vectors.flatMap(v => v.expect.ok ? [] : [v.expect.code]));
  expect([...codes].sort()).toEqual(["featureNotSupported", "invalidDid", "invalidLog", "invalidOptions", "notFound"]);
  expect(new Set(shared.vectors.map(v => v.name)).size).toBe(shared.vectors.length);
});

for (const vector of shared.vectors) {
  test(`vector ${vector.name}: ${vector.note}`, async () => {
    const result = resolveVhLog(vector.did, vector.log as VhLogEntry[], { ...(vector.options as object | undefined), now: Date.parse(shared.now) });
    if (vector.expect.ok) {
      const resolved = await result;
      expect(resolved.meta.versionNumber).toBe(vector.expect.versionNumber);
      expect(resolved.meta.deactivated).toBe(vector.expect.deactivated);
      expect(resolved.doc === null).toBe(vector.expect.documentNull === true);
    } else {
      // Not just any failure: the one the vector is about.
      await expect(result).rejects.toMatchObject({ name: "VhResolutionError", code: vector.expect.code, message: expect.stringContaining(vector.expect.reason) });
    }
  });
}

// ---- the did:web shadow ----------------------------------------------------------------------------------------------

test("the shadow vectors cover the derivation and the ways a did:web document can be wrong", () => {
  expect(shared.shadows.filter(v => v.ok).length).toBeGreaterThanOrEqual(1);
  expect(shared.shadows.filter(v => !v.ok).length).toBeGreaterThanOrEqual(10);
  expect(new Set(shared.shadows.map(v => v.name)).size).toBe(shared.shadows.length);
});

for (const vector of shared.shadows) {
  test(`shadow ${vector.name}: ${vector.note}`, () => {
    expect(checkDidWebShadow(vector.vhDocument as never, vector.didWeb, vector.webDocument).ok).toBe(vector.ok);
  });
}
