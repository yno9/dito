import { afterEach, expect, test } from "vitest";
import { createIdentityMaterial } from "../packages/wallet/src/keys.ts";
import { createGenesisEntry } from "../packages/wallet/src/vh-ops.ts";
import { CredentialRequiredError, hostForSrc, isGitHubSrc } from "../packages/wallet/src/host.ts";

const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });

async function sample() {
  const identity = await createIdentityMaterial();
  const genesis = await createGenesisEntry({ root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare, src: "https://alice.did.md" });
  return { genesis, entries: [genesis] };
}

test("hostForSrc routes did.md and GitHub locations to different adapters", () => {
  expect(hostForSrc("https://alice.did.md").kind).toBe("http");
  expect(hostForSrc("https://alice.github.io").kind).toBe("github");
  expect(isGitHubSrc("https://alice.github.io")).toBe(true);
  expect(isGitHubSrc("https://alice.did.md")).toBe(false);
  expect(isGitHubSrc("https://github.io.evil.example")).toBe(false);
});

test("logUrl on each adapter is the did.jsonl of its own location", () => {
  expect(hostForSrc("https://alice.did.md").logUrl("https://alice.did.md")).toBe("https://alice.did.md/.well-known/did.jsonl");
  expect(hostForSrc("https://alice.github.io").logUrl("https://alice.github.io")).toBe("https://alice.github.io/.well-known/did.jsonl");
});

test("GitHub host requires a PAT before any write", async () => {
  const { entries } = await sample();
  await expect(hostForSrc("https://alice.github.io").publish({ src: "https://alice.github.io", entries })).rejects.toBeInstanceOf(CredentialRequiredError);
});

test("did.md host appends one entry with POST and never asks for a credential", async () => {
  const { genesis } = await sample();
  const host = hostForSrc("https://alice.did.md");
  const calls: Array<{ url: string; method: string; body?: string }> = [];
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    calls.push({ url, method: init?.method ?? "GET", body: typeof init?.body === "string" ? init.body : undefined });
    return new Response("ok", { status: 200 });
  }) as typeof fetch;

  const result = await host.publish({ src: "https://alice.did.md", entries: [genesis], mode: "append" });
  expect(result.kind).toBe("http");
  expect(result.did).toBe(genesis.state.id);
  expect(result.verifiedLive).toBe(true);
  expect(calls).toHaveLength(1);
  expect(calls[0]!.method).toBe("POST");
  expect(calls[0]!.url).toBe("https://alice.did.md/.well-known/did.jsonl");
  expect(calls[0]!.body).toBe(`${JSON.stringify(genesis)}\n`);
});

test("GitHub remove without a PAT is a credential error, and a 404 remove on did.md is already-gone success", async () => {
  const { genesis } = await sample();
  const did = genesis.state.id;
  await expect(
    hostForSrc("https://alice.github.io").remove("https://alice.github.io", did, { privateKey: new Uint8Array(32), multikey: "z" }),
  ).rejects.toBeInstanceOf(CredentialRequiredError);

  // did.md remove: 404 already-gone is success (found live 2026-09-29).
  globalThis.fetch = (async () => new Response("Not Found", { status: 404 })) as typeof fetch;
  const identity = await createIdentityMaterial();
  await expect(hostForSrc("https://alice.did.md").remove("https://alice.did.md", did, identity.sign)).resolves.toBe(true);
});
