import { afterEach, expect, test } from "bun:test";
import { buildGenesis, createIdentityMaterial, preparePortableImport } from "../packages/wallet/src/did-webvh.ts";
import {
  CredentialRequiredError,
  hostForDid,
  isGitHubHostedDid,
  serialiseEntries,
} from "../packages/wallet/src/host.ts";

const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json" } });
}

async function sampleMove() {
  const identity = await createIdentityMaterial();
  const genesis = await buildGenesis({
    username: "alice", domain: "did.md", root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare,
  });
  const moved = await preparePortableImport({
    entries: [genesis], username: "alice", domain: "github.io", masterSeed: identity.masterSeed,
  });
  return { genesis, moved, entries: [genesis, moved.entry] };
}

test("hostForDid routes did.md and GitHub DIDs to different adapters", async () => {
  const { genesis, moved } = await sampleMove();
  expect(hostForDid(genesis.state.id).kind).toBe("http");
  expect(hostForDid(moved.did).kind).toBe("github");
  expect(isGitHubHostedDid(moved.did)).toBe(true);
  expect(isGitHubHostedDid(genesis.state.id)).toBe(false);
});

test("logUrl on each adapter matches didToLogUrl for its own DID", async () => {
  const { genesis, moved } = await sampleMove();
  expect(hostForDid(genesis.state.id).logUrl(genesis.state.id)).toBe("https://alice.did.md/.well-known/did.jsonl");
  expect(hostForDid(moved.did).logUrl(moved.did)).toBe("https://alice.github.io/.well-known/did.jsonl");
});

test("GitHub host requires a PAT before any write", async () => {
  const { moved, entries } = await sampleMove();
  const host = hostForDid(moved.did);
  await expect(host.publish({ entries })).rejects.toBeInstanceOf(CredentialRequiredError);
});

test("did.md host appends one entry with POST and never asks for a credential", async () => {
  const { genesis } = await sampleMove();
  const host = hostForDid(genesis.state.id);
  const calls: Array<{ url: string; method: string; body?: string }> = [];
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    calls.push({ url, method: init?.method ?? "GET", body: typeof init?.body === "string" ? init.body : undefined });
    return new Response("ok", { status: 200 });
  }) as typeof fetch;

  const result = await host.publish({ entries: [genesis], mode: "append" });
  expect(result.kind).toBe("http");
  expect(result.verifiedLive).toBe(true);
  expect(calls).toHaveLength(1);
  expect(calls[0]!.method).toBe("POST");
  expect(calls[0]!.url).toBe("https://alice.did.md/.well-known/did.jsonl");
  expect(calls[0]!.body).toBe(`${JSON.stringify(genesis)}\n`);
});

test("GitHub host rewrite uses the full log and treats 404 remove as success on did.md", async () => {
  const { genesis, moved, entries } = await sampleMove();

  // GitHub remove without a PAT is a credential error, not a silent no-op.
  const github = hostForDid(moved.did);
  await expect(
    github.remove(moved.did, { privateKey: new Uint8Array(32), multikey: "z" }),
  ).rejects.toBeInstanceOf(CredentialRequiredError);

  // did.md remove: 404 already-gone is success (found live 2026-09-29).
  const didMd = hostForDid(genesis.state.id);
  globalThis.fetch = (async () => new Response("Not Found", { status: 404 })) as typeof fetch;
  await expect(didMd.remove(genesis.state.id, { privateKey: new Uint8Array(32), multikey: "z" })).resolves.toBe(true);
});

test("serialiseEntries writes compact JSONL with a trailing newline", async () => {
  const { genesis } = await sampleMove();
  const body = serialiseEntries([genesis]);
  expect(body.endsWith("\n")).toBe(true);
  expect(body.trimEnd().split("\n")).toHaveLength(1);
  expect(JSON.parse(body.trim()).versionId).toBe(genesis.versionId);
});
