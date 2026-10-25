import { expect, test } from "vitest";
import { isHostedAt, locationHosts, parseLoginHost } from "../packages/wallet/src/login-hint.ts";
import { withLocation } from "../packages/vh/src/index.ts";

test("accepts did.md subdomains and bring-your-own domains", () => {
  expect(parseLoginHost("alice.did.md")).toBe("alice.did.md");
  expect(parseLoginHost("digitalcommons.jp")).toBe("digitalcommons.jp");
  expect(parseLoginHost("id.example.co.uk")).toBe("id.example.co.uk");
  expect(parseLoginHost("xn--tst-6la.example")).toBe("xn--tst-6la.example");
});

test("normalizes case", () => {
  expect(parseLoginHost("DigitalCommons.JP")).toBe("digitalcommons.jp");
});

test("rejects anything that is not a plain DNS hostname", () => {
  for (const bad of [
    "", "did", "localhost", ".did.md", "alice..did.md", "alice.did.md.", "-a.did.md", "a-.did.md",
    "alice.did.md:8443", "https://alice.did.md", "alice.did.md/path", "alice@did.md", "alice did.md",
    "127.0.0.1", "1.2.3.4", "[::1]", "a.b.123", `${"a".repeat(64)}.did.md`, `${"a.".repeat(130)}md`,
  ]) expect(parseLoginHost(bad)).toBeNull();
  expect(parseLoginHost(undefined)).toBeNull();
  expect(parseLoginHost(null)).toBeNull();
  expect(parseLoginHost(42)).toBeNull();
});

test("matches an identity by the locations its own document names", () => {
  const did = `did:vh:${"Q".repeat(46)}`;
  const at = (...srcs: string[]) => srcs.reduce<Record<string, any>>((document, src) => withLocation(document, did, src), { id: did });
  expect(locationHosts(did, at("https://digitalcommons.jp"))).toEqual(["digitalcommons.jp"]);
  expect(isHostedAt(did, at("https://digitalcommons.jp"), "digitalcommons.jp")).toBe(true);
  expect(isHostedAt(did, at("https://alice.did.md"), "alice.did.md")).toBe(true);
  // another host, an identity with no location, and a location under a path never match a plain host
  expect(isHostedAt(did, at("https://alice.did.md"), "digitalcommons.jp")).toBe(false);
  expect(isHostedAt(did, { id: did }, "alice.did.md")).toBe(false);
  expect(isHostedAt(did, at("https://digitalcommons.jp/users/bob"), "bob.digitalcommons.jp")).toBe(false);
});
