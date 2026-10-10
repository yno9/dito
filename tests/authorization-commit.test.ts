import { expect, test } from "vitest";
import { commitAuthorization } from "../packages/wallet/src/authorization-commit.ts";

function recorder() {
  const calls: string[] = [];
  return { calls, note: (name: string) => calls.push(name) };
}

test("accepts, then persists, then navigates -- in that order", async () => {
  const { calls, note } = recorder();
  await commitAuthorization({
    accept: async () => { note("accept"); return { code: "c1" }; },
    persist: async accepted => { note(`persist:${accepted.code}`); },
    navigate: accepted => { note(`navigate:${accepted.code}`); },
  });
  expect(calls).toEqual(["accept", "persist:c1", "navigate:c1"]);
});

test("a failed accept writes nothing locally and never navigates", async () => {
  const { calls, note } = recorder();
  await expect(commitAuthorization({
    accept: async () => { note("accept"); throw new Error("bridge said no"); },
    persist: async () => { note("persist"); },
    navigate: () => { note("navigate"); },
  })).rejects.toThrow("bridge said no");
  expect(calls).toEqual(["accept"]);
});

test("a failed persist does not tell the relying party", async () => {
  const { calls, note } = recorder();
  await expect(commitAuthorization({
    accept: async () => { note("accept"); return 1; },
    persist: async () => { note("persist"); throw new Error("storage full"); },
    navigate: () => { note("navigate"); },
  })).rejects.toThrow("storage full");
  expect(calls).toEqual(["accept", "persist"]);
});

test("persist waits for accept even when accept is slow", async () => {
  const { calls, note } = recorder();
  await commitAuthorization({
    accept: async () => { await new Promise(resolve => setTimeout(resolve, 20)); note("accept"); return 0; },
    persist: async () => { note("persist"); },
    navigate: () => { note("navigate"); },
  });
  expect(calls).toEqual(["accept", "persist", "navigate"]);
});
