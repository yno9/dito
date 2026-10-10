import { expect, test } from "vitest";
import { didHost, didIsHostedAt, parseLoginHost } from "../packages/wallet/src/login-hint.ts";

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

test("matches an identity by the host segment of its DID", () => {
  const scid = "QmZdfGg8BAxEMLvHRC1RwDVcthg66akuBzJoeLvRdHXwQz";
  expect(didHost(`did:webvh:${scid}:digitalcommons.jp`)).toBe("digitalcommons.jp");
  expect(didIsHostedAt(`did:webvh:${scid}:digitalcommons.jp`, "digitalcommons.jp")).toBe(true);
  expect(didIsHostedAt(`did:webvh:${scid}:alice.did.md`, "alice.did.md")).toBe(true);
  // another host, another identity, a path-scoped DID, and non-webvh DIDs never match
  expect(didIsHostedAt(`did:webvh:${scid}:alice.did.md`, "digitalcommons.jp")).toBe(false);
  expect(didIsHostedAt(`did:webvh:${scid}:digitalcommons.jp:users:bob`, "digitalcommons.jp")).toBe(false);
  expect(didIsHostedAt("did:web:digitalcommons.jp", "digitalcommons.jp")).toBe(false);
  expect(didIsHostedAt(undefined, "digitalcommons.jp")).toBe(false);
});
