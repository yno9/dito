import { describe, expect, test } from "vitest";
import { uncachedUrl } from "../packages/vh/src/index.ts";

describe("uncachedUrl", () => {
  test("adds a query no cache has seen, and keeps the rest of the URL", () => {
    expect(uncachedUrl("https://alice.did.md/.well-known/did.jsonl", 1792544526736)).toBe("https://alice.did.md/.well-known/did.jsonl?_=1792544526736");
    expect(uncachedUrl("https://alice.did.md/.well-known/did.jsonl?x=1", 5)).toBe("https://alice.did.md/.well-known/did.jsonl?x=1&_=5");
    expect(uncachedUrl(new URL("https://alice.did.md/a/did.jsonl"), 7)).toBe("https://alice.did.md/a/did.jsonl?_=7");
  });

  test("replaces an earlier cache-buster instead of stacking them, and a later call is a different URL", () => {
    expect(uncachedUrl("https://alice.did.md/.well-known/did.jsonl?_=1", 2)).toBe("https://alice.did.md/.well-known/did.jsonl?_=2");
    expect(uncachedUrl("https://alice.did.md/x", 1)).not.toBe(uncachedUrl("https://alice.did.md/x", 2));
  });

  test("the default is the current time", () => {
    const before = Date.now();
    const value = Number(new URL(uncachedUrl("https://alice.did.md/x")).searchParams.get("_"));
    expect(value).toBeGreaterThanOrEqual(before);
    expect(value).toBeLessThanOrEqual(Date.now());
  });
});
