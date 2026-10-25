import { afterEach, expect, test } from "vitest";
import { createIdentityMaterial } from "../packages/wallet/src/keys.ts";
import { createGenesisEntry, prepareLocationEntry } from "../packages/wallet/src/vh-ops.ts";
import {
  buildDidJson,
  buildPublishFiles,
  commitFiles,
  ensurePages,
  ensureRepo,
  fromBase64Utf8,
  githubDidLocation,
  githubErrorMessage,
  normalizeLogin,
  publishToGitHub,
  removeGitHubDidFiles,
  toBase64Utf8,
  validateBeforePublish,
  verifyPublishedLog,
  waitForPagesBuild,
  waitForPublish,
} from "../packages/wallet/src/github-host.ts";
import { deriveDidWebDocument, parseVhLog, serializeVhLog } from "../packages/vh/src/index.ts";

const serialise = serializeVhLog;

const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });

type FetchCall = { url: string; method: string; body?: string };

function mockFetch(handler: (url: string, init?: RequestInit) => Response | Promise<Response>) {
  const calls: FetchCall[] = [];
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    calls.push({ url, method: init?.method ?? "GET", body: typeof init?.body === "string" ? init.body : undefined });
    return handler(url, init);
  }) as typeof fetch;
  return calls;
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json" } });
}

test("githubDidLocation builds a user-site location and lowercases login", () => {
  const location = githubDidLocation("Alice");
  expect(location.login).toBe("alice");
  expect(location.repo).toBe("alice.github.io");
  expect(location.domain).toBe("alice.github.io");
  expect(location.segments).toEqual([]);
  expect(location.contentsPath).toBe(".well-known/did.jsonl");
  expect(location.nojekyllPath).toBe(".nojekyll");
  expect(location.didJsonPath).toBe(".well-known/did.json");
  expect(location.src).toBe("https://alice.github.io");
  expect(location.webDid).toBe("did:web:alice.github.io");
  expect(location.publicUrl).toBe("https://alice.github.io/.well-known/did.jsonl");
});

test("normalizeLogin rejects names that are not GitHub account logins", () => {
  expect(normalizeLogin("Bob-Dev")).toBe("bob-dev");
  expect(() => normalizeLogin("")).toThrow();
  expect(() => normalizeLogin("has space")).toThrow();
  expect(() => normalizeLogin("-leading")).toThrow();
});

test("base64 UTF-8 round-trips did:vh JSON", () => {
  const sample = '{"state":{"id":"did:vh:Qm","name":"日本語 🎉"}}\n';
  expect(fromBase64Utf8(toBase64Utf8(sample))).toBe(sample);
  expect(fromBase64Utf8(toBase64Utf8("ascii only"))).toBe("ascii only");
});

test("githubErrorMessage maps status codes to actionable wording", () => {
  expect(githubErrorMessage({ status: 401, message: "Bad credentials" })).toMatch(/new classic PAT/i);
  expect(githubErrorMessage({ status: 403, message: "rate limit exceeded" })).toMatch(/rate limit/i);
  expect(githubErrorMessage({ status: 403, message: "upgrade" })).toMatch(/private-repo Pages|permission/i);
  expect(githubErrorMessage({ status: 404, message: "Not Found" })).toMatch(/not found/i);
  expect(githubErrorMessage({ status: 409, message: "Conflict" })).toMatch(/Try Publish again/i);
});

test("the did.json of a GitHub site is the did:web document derived from the log: the DID becomes did:web:<login>.github.io, alsoKnownAs only the did:vh", () => {
  const did = `did:vh:${"Q".repeat(46)}`;
  const state = {
    id: did,
    verificationMethod: [{ id: "#pass-1", type: "Multikey", controller: did, publicKeyMultibase: "z6Mkf5rGMoatjnh5dBeMpxkTm1VJwGqLrH6kVzq3q3q3q3q3" }],
    authentication: ["#pass-1"],
    service: [],
    alsoKnownAs: ["did:web:alice.github.io", `${did}?src=https://alice.github.io`],
  };
  const derived = JSON.parse(buildDidJson(state, "did:web:alice.github.io"));
  expect(derived).toEqual(deriveDidWebDocument(state, "did:web:alice.github.io"));
  expect(derived.id).toBe("did:web:alice.github.io");
  expect(derived.verificationMethod[0].controller).toBe("did:web:alice.github.io");
  expect(derived.alsoKnownAs).toEqual([did]);
  expect(JSON.stringify(derived)).not.toContain("#files");
});

test("buildPublishFiles writes did.jsonl, empty .nojekyll and did.json in one list", async () => {
  const identity = await createIdentityMaterial();
  const location = githubDidLocation("alice");
  const genesis = await createGenesisEntry({ root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare, src: location.src });
  expect(genesis.state.alsoKnownAs).toContain(location.webDid);
  const files = buildPublishFiles([genesis], location);
  expect(files.map(f => f.path)).toEqual([".well-known/did.jsonl", ".nojekyll", ".well-known/did.json"]);
  expect(files[0]!.content.endsWith("\n")).toBe(true);
  expect(files[0]!.content.split("\n").filter(Boolean)).toHaveLength(1);
  expect(files[1]!.content).toBe("");
  const mirror = JSON.parse(files[2]!.content);
  expect(mirror.id).toBe("did:web:alice.github.io");
  expect(mirror.alsoKnownAs).toEqual([genesis.state.id]);
});

test("validateBeforePublish accepts a correct log and rejects tampering before any network write", async () => {
  const identity = await createIdentityMaterial();
  const location = githubDidLocation("alice");
  const genesis = await createGenesisEntry({ root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare, src: location.src });
  const ok = await validateBeforePublish([genesis], location.webDid);
  expect(ok.versionId).toBe(genesis.versionId);

  // Entry hash / SCID mismatch.
  const forged = JSON.parse(JSON.stringify(genesis));
  forged.state = { ...forged.state, name: "tampered" };
  await expect(validateBeforePublish([forged], location.webDid)).rejects.toThrow(/hash|SCID/i);

  // Missing proof.
  const unsigned = { ...JSON.parse(JSON.stringify(genesis)), proof: [] };
  await expect(validateBeforePublish([unsigned], location.webDid)).rejects.toThrow(/proof/i);

  // Another location: the document does not name it.
  await expect(validateBeforePublish([genesis], "did:web:other.example")).rejects.toThrow(/must name did:web:other\.example/i);
});

test("an identity moves to <login>.github.io with one location entry, keeping its DID, and the resulting log validates", async () => {
  const identity = await createIdentityMaterial();
  const genesis = await createGenesisEntry({ root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare, src: "https://alice.did.md" });
  const location = githubDidLocation("Alice");
  const prepared = await prepareLocationEntry({
    entries: [genesis], src: location.src, previousSrc: "https://alice.did.md", masterSeed: identity.masterSeed, currentSpareIndex: 0,
  });
  expect(prepared.state.id).toBe(genesis.state.id);
  expect(prepared.state.alsoKnownAs).toContain(location.webDid);
  expect(prepared.state.alsoKnownAs).not.toContain("did:web:alice.did.md");

  const latest = await validateBeforePublish([genesis, prepared.entry], location.webDid);
  expect(latest.versionId).toBe(prepared.entry.versionId);
});

async function sampleMove() {
  const identity = await createIdentityMaterial();
  const genesis = await createGenesisEntry({ root: identity.root, sign: identity.sign, nextSpare: identity.nextSpare, src: "https://alice.did.md" });
  const location = githubDidLocation("alice");
  const moved = await prepareLocationEntry({
    entries: [genesis], src: location.src, previousSrc: "https://alice.did.md", masterSeed: identity.masterSeed, currentSpareIndex: 0,
  });
  return { identity, genesis, moved: { ...moved, did: genesis.state.id }, entries: [genesis, moved.entry], location };
}

test("commitFiles writes all paths in one Git Data commit and retries once on ref conflict", async () => {
  const { entries, location } = await sampleMove();
  const files = buildPublishFiles(entries, location);
  let dataApiCalls = 0;
  let refUpdates = 0;
  const blobShas = new Map<string, string>();

  mockFetch((url, init) => {
    const method = init?.method ?? "GET";
    // Octokit percent-encodes path params (heads/main → heads%2Fmain).
    if (url.includes("/git/ref/") && method === "GET") {
      dataApiCalls += 1;
      return json({ object: { sha: `head-${dataApiCalls}` } });
    }
    if (url.endsWith("/git/blobs") && method === "POST") {
      dataApiCalls += 1;
      const body = JSON.parse(init!.body as string);
      const sha = `blob-${blobShas.size + 1}`;
      blobShas.set(sha, body.content);
      return json({ sha }, 201);
    }
    if (url.endsWith("/git/trees") && method === "POST") {
      dataApiCalls += 1;
      return json({ sha: "tree-1" }, 201);
    }
    if (url.endsWith("/git/commits") && method === "POST") {
      dataApiCalls += 1;
      return json({ sha: `commit-${dataApiCalls}` }, 201);
    }
    if (url.includes("/git/refs/") && method === "PATCH") {
      refUpdates += 1;
      // First update conflicts, second succeeds.
      if (refUpdates === 1) return json({ message: "Reference update failed: conflict" }, 409);
      return json({ object: { sha: "commit-final" } }, 200);
    }
    return json({ message: `unexpected ${method} ${url}` }, 500);
  });

  const result = await commitFiles("token", location, "main", files, "publish");
  expect(result.retried).toBe(true);
  expect(result.commitSha.startsWith("commit-")).toBe(true);
  expect(refUpdates).toBe(2);
  // One ref read + 3 blobs + 1 tree + 1 commit per attempt (×2).
  expect(dataApiCalls).toBeGreaterThan(5);
});

test("ensurePages creates Pages on 404 and maps private-repo Free-plan failures to a manual instruction", async () => {
  const location = githubDidLocation("alice");

  mockFetch((url, init) => {
    if (url.endsWith("/pages") && (init?.method ?? "GET") === "GET") return json({ message: "Not Found" }, 404);
    if (url.endsWith("/pages") && init?.method === "POST") return json({ status: "built", html_url: "https://alice.github.io" }, 201);
    return json({ message: "nope" }, 500);
  });
  await expect(ensurePages("token", location, "main")).resolves.toMatchObject({ created: true });

  mockFetch((url, init) => {
    if (url.endsWith("/pages") && (init?.method ?? "GET") === "GET") return json({ message: "Not Found" }, 404);
    if (url.endsWith("/pages") && init?.method === "POST") return json({ message: "upgrade to Pro" }, 403);
    return json({ message: "nope" }, 500);
  });
  await expect(ensurePages("token", location, "main")).rejects.toThrow(/public/i);
});

test("ensurePages reports workflow vs legacy build_type so waiters pick the right status API", async () => {
  const location = githubDidLocation("alice");
  mockFetch((url) => {
    if (url.endsWith("/pages")) return json({ build_type: "workflow", status: "built", html_url: "https://alice.github.io" });
    return json({ message: "nope" }, 500);
  });
  await expect(ensurePages("token", location, "main")).resolves.toMatchObject({ created: false, buildType: "workflow", status: "built" });
});

test("ensureRepo creates a missing user-site repo as public and leaves an existing private repo alone", async () => {
  const location = githubDidLocation("alice");

  mockFetch((url, init) => {
    if (url.endsWith("/repos/alice/alice.github.io") && (init?.method ?? "GET") === "GET") return json({ message: "Not Found" }, 404);
    if (url.endsWith("/user/repos") && init?.method === "POST") {
      const body = JSON.parse(init!.body as string);
      expect(body.name).toBe("alice.github.io");
      expect(body.private).toBe(false);
      return json({ default_branch: "main", private: false, html_url: "https://github.com/alice/alice.github.io" }, 201);
    }
    return json({ message: "nope" }, 500);
  });
  await expect(ensureRepo("token", location)).resolves.toMatchObject({ defaultBranch: "main", private: false });

  mockFetch((url) => {
    if (url.endsWith("/repos/alice/alice.github.io")) return json({ default_branch: "main", private: true, html_url: "https://github.com/alice/alice.github.io" }, 200);
    return json({ message: "nope" }, 500);
  });
  await expect(ensureRepo("token", location)).resolves.toMatchObject({ private: true });
});

test("waitForPublish succeeds once Pages serves the expected versionId and times out otherwise", async () => {
  const body = JSON.stringify({ versionId: "2-abc" }) + "\n";
  let attempts = 0;
  mockFetch(() => {
    attempts += 1;
    if (attempts < 3) return new Response("not yet", { status: 404 });
    return new Response(body, { status: 200 });
  });
  await expect(
    waitForPublish("https://alice.github.io/.well-known/did.jsonl", "2-abc", { intervalMs: 1, timeoutMs: 1000 }),
  ).resolves.toMatchObject({ ok: true, versionId: "2-abc" });

  mockFetch(() => new Response("", { status: 404 }));
  await expect(
    waitForPublish("https://alice.github.io/.well-known/did.jsonl", "2-abc", { intervalMs: 1, timeoutMs: 5 }),
  ).rejects.toThrow(/Recheck/i);
});

test("waitForPagesBuild returns when status is built and surfaces errored builds", async () => {
  mockFetch((url) => {
    if (url.endsWith("/pages/builds/latest")) return json({ status: "built" }, 200);
    return json({ message: "nope" }, 500);
  });
  await expect(waitForPagesBuild("token", githubDidLocation("alice"), { intervalMs: 1, timeoutMs: 500, buildType: "legacy" })).resolves.toMatchObject({ status: "built", inconclusive: false });

  mockFetch((url) => {
    if (url.endsWith("/pages/builds/latest")) return json({ status: "errored", error: { message: "jekyll failed" } }, 200);
    return json({ message: "nope" }, 500);
  });
  await expect(waitForPagesBuild("token", githubDidLocation("alice"), { intervalMs: 1, timeoutMs: 500, buildType: "legacy" })).rejects.toThrow(/jekyll failed/i);
});

test("waitForPagesBuild follows workflow (Actions) Pages via GET /pages, not builds/latest", async () => {
  // Regression 2026-09-29: actions/deploy-pages reported success while
  // Publish sat on step 6, because builds/latest never became "built" for
  // workflow-type sites.
  let pagesReads = 0;
  mockFetch((url) => {
    if (url.endsWith("/pages") && !url.endsWith("/pages/builds/latest")) {
      pagesReads += 1;
      return json({ build_type: "workflow", status: pagesReads < 2 ? "building" : "built" });
    }
    // builds/latest must NOT be consulted for workflow builds.
    return json({ message: `unexpected ${url}` }, 500);
  });
  await expect(
    waitForPagesBuild("token", githubDidLocation("alice"), { intervalMs: 1, timeoutMs: 500, buildType: "workflow" }),
  ).resolves.toMatchObject({ status: "built", buildType: "workflow", inconclusive: false });

  // Timeout on a still-building workflow site is inconclusive, not fatal.
  mockFetch((url) => {
    if (url.endsWith("/pages") && !url.endsWith("/pages/builds/latest")) return json({ build_type: "workflow", status: "building" });
    return json({ message: `unexpected ${url}` }, 500);
  });
  await expect(
    waitForPagesBuild("token", githubDidLocation("alice"), { intervalMs: 1, timeoutMs: 5, buildType: "workflow" }),
  ).resolves.toMatchObject({ inconclusive: true, buildType: "workflow" });
});

test("publishToGitHub never writes to GitHub when local validation fails", async () => {
  const { genesis } = await sampleMove();
  // Only the genesis, with a forged name -- fails entry-hash check.
  const forged = JSON.parse(JSON.stringify(genesis));
  forged.state = { ...forged.state, name: "tampered" };
  const calls: FetchCall[] = [];
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    calls.push({ url, method: init?.method ?? "GET", body: typeof init?.body === "string" ? init.body : undefined });
    if (url.endsWith("/user")) return json({ login: "alice" });
    return json({ message: "must not be called" }, 500);
  }) as typeof fetch;

  await expect(
    publishToGitHub({
      token: "secret-token",
      entries: [forged],
      onProgress: () => {},
      intervalMs: 1,
      timeoutMs: 10,
    }),
  ).rejects.toThrow(/hash|verification|SCID/i);

  const writes = calls.filter(call => call.method !== "GET");
  expect(writes).toEqual([]);
});

test("publishToGitHub drives the full happy path against a mocked GitHub", async () => {
  const { entries, location, moved } = await sampleMove();
  const logBody = serialise(entries);
  const mirrorBody = buildDidJson(entries.at(-1)!.state as any, location.webDid);
  const expectedVersionId = entries.at(-1)!.versionId;
  let pagesStatusReads = 0;

  mockFetch((url, init) => {
    const method = init?.method ?? "GET";
    if (url.endsWith("/user") && method === "GET") return json({ login: "Alice" });
    if (url.endsWith("/repos/alice/alice.github.io") && method === "GET") return json({ default_branch: "main", private: false });
    if (url.includes("/git/ref/") && method === "GET") return json({ object: { sha: "head" } });
    if (url.endsWith("/git/blobs") && method === "POST") return json({ sha: `blob-${Math.random()}` }, 201);
    if (url.endsWith("/git/trees") && method === "POST") return json({ sha: "tree" }, 201);
    if (url.endsWith("/git/commits") && method === "POST") return json({ sha: "commit" }, 201);
    if (url.includes("/git/refs/") && method === "PATCH") return json({ object: { sha: "commit" } });
    // Already-enabled workflow Pages (this is the shape that stalled Publish).
    if (url.endsWith("/pages") && method === "GET" && !url.includes("builds")) {
      pagesStatusReads += 1;
      return json({ build_type: "workflow", status: pagesStatusReads === 1 ? "building" : "built", html_url: "https://alice.github.io" });
    }
    if (url.endsWith("/pages") && method === "POST") return json({ status: "built" }, 201);
    if (url.endsWith("/pages/builds/latest")) return json({ message: "must not use legacy builds API for workflow Pages" }, 500);
    return json({ message: `unexpected ${method} ${url}` }, 500);
  });

  const steps: string[] = [];
  const result = await publishToGitHub({
    token: "secret-token",
    entries,
    onProgress: step => steps.push(step),
    intervalMs: 1,
    timeoutMs: 500,
    fetchImpl: (async (input: string | URL | Request) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url === location.publicUrl) return new Response(logBody, { status: 200 });
      if (url === location.didJsonPublicUrl) return new Response(mirrorBody, { status: 200 });
      return new Response("nope", { status: 404 });
    }) as typeof fetch,
  });

  expect(result.login).toBe("alice");
  expect(result.did).toBe(moved.did);
  expect(result.publicUrl).toBe(location.publicUrl);
  expect(result.versionId).toBe(expectedVersionId);
  expect(result.verifiedLive).toBe(true);
  // wait-build is a no-op for workflow Pages -- never polls builds/latest.
  expect(steps).toEqual([
    "verify-token", "validate", "ensure-repo", "commit", "enable-pages", "wait-build", "wait-publish", "verify-published", "verify-mirror", "done",
  ]);
});

test("verifyPublishedLog re-checks chain integrity and the last versionId", async () => {
  const { entries, location } = await sampleMove();
  const body = serialise(entries);
  await expect(verifyPublishedLog(body, location.webDid, entries.at(-1)!.versionId)).resolves.toBeUndefined();
  await expect(verifyPublishedLog(body, location.webDid, "1-wrong")).rejects.toThrow(/version/i);
  const broken = body.replace(entries.at(-1)!.versionId, "9-fake");
  await expect(verifyPublishedLog(broken, location.webDid, "9-fake")).rejects.toThrow();
});

test("publishToGitHub reports verifiedLive=false when Pages is not serving the log yet", async () => {
  const { entries, location, moved } = await sampleMove();
  mockFetch((url, init) => {
    const method = init?.method ?? "GET";
    if (url.endsWith("/user") && method === "GET") return json({ login: "alice" });
    if (url.endsWith("/repos/alice/alice.github.io") && method === "GET") return json({ default_branch: "main", private: false });
    if (url.includes("/git/ref/") && method === "GET") return json({ object: { sha: "head" } });
    if (url.endsWith("/git/blobs") && method === "POST") return json({ sha: "blob" }, 201);
    if (url.endsWith("/git/trees") && method === "POST") return json({ sha: "tree" }, 201);
    if (url.endsWith("/git/commits") && method === "POST") return json({ sha: "commit" }, 201);
    if (url.includes("/git/refs/") && method === "PATCH") return json({ object: { sha: "commit" } });
    if (url.endsWith("/pages") && method === "GET") return json({ message: "Not Found" }, 404);
    if (url.endsWith("/pages") && method === "POST") return json({ status: "built" }, 201);
    if (url.endsWith("/pages/builds/latest")) return json({ status: "built" });
    return json({ message: `unexpected ${method} ${url}` }, 500);
  });
  const result = await publishToGitHub({
    token: "secret-token",
    entries,
    intervalMs: 1,
    timeoutMs: 5,
    fetchImpl: (async () => new Response("not yet", { status: 404 })) as typeof fetch,
  });
  expect(result.verifiedLive).toBe(false);
  expect(result.did).toBe(moved.did);
  expect(result.publicUrl).toBe(location.publicUrl);
});

test("removeGitHubDidFiles deletes only the DID files via Contents API, not the repository", async () => {
  const deletedPaths: string[] = [];
  let deleteRepoCalls = 0;
  let deletes = 0;
  mockFetch((url, init) => {
    const method = init?.method ?? "GET";
    if (url.endsWith("/user")) return json({ login: "alice" });
    if (url.endsWith("/repos/alice/alice.github.io") && method === "GET") return json({ default_branch: "main", private: false });
    if (method === "DELETE" && /\/contents\//.test(url)) {
      deletes += 1;
      const path = decodeURIComponent(url.split("/contents/")[1]!.split("?")[0]!);
      deletedPaths.push(path);
      return json({ commit: { sha: `del-${deletes}` } });
    }
    if (method === "DELETE") {
      deleteRepoCalls += 1;
      return json({ message: "unexpected repo delete" }, 500);
    }
    if (url.includes("/contents/") && method === "GET") {
      // Present before any delete; gone afterward (verify pass).
      return deletes === 0 ? json({ sha: `sha-${Math.random()}` }) : json({ message: "Not Found" }, 404);
    }
    // Git Data must not be used for delete (tree sha:null was a silent no-op).
    return json({ message: `unexpected ${method} ${url}` }, 500);
  });

  const result = await removeGitHubDidFiles("token");
  expect(result.removed).toEqual([".well-known/did.jsonl", ".well-known/did.json"]);
  expect(result.commitSha).toMatch(/^del-/);
  expect(deletedPaths).toEqual([".well-known/did.jsonl", ".well-known/did.json"]);
  expect(deleteRepoCalls).toBe(0);
  expect(deletes).toBe(2);
});

test("removeGitHubDidFiles is a quiet no-op when the files are already gone", async () => {
  const calls: string[] = [];
  mockFetch((url, init) => {
    const method = init?.method ?? "GET";
    calls.push(`${method} ${url}`);
    if (url.endsWith("/user")) return json({ login: "alice" });
    if (url.endsWith("/repos/alice/alice.github.io") && method === "GET") return json({ default_branch: "main", private: false });
    if (url.includes("/contents/")) return json({ message: "Not Found" }, 404);
    return json({ message: `unexpected ${method} ${url}` }, 500);
  });

  const result = await removeGitHubDidFiles("token");
  expect(result).toEqual({ removed: [], commitSha: null });
  expect(calls.some(call => call.includes("/git/trees") || call.includes("/git/commits") || methodIsDelete(call))).toBe(false);
});

function methodIsDelete(call: string) {
  return call.startsWith("DELETE ");
}

test("removeGitHubDidFiles fails loudly if a file is still there after delete", async () => {
  mockFetch((url, init) => {
    const method = init?.method ?? "GET";
    if (url.endsWith("/user")) return json({ login: "alice" });
    if (url.endsWith("/repos/alice/alice.github.io") && method === "GET") return json({ default_branch: "main", private: false });
    if (method === "DELETE" && /\/contents\//.test(url)) return json({ commit: { sha: "del" } });
    if (url.includes("/contents/") && method === "GET") return json({ sha: "still-here" });
    return json({ message: `unexpected ${method} ${url}` }, 500);
  });

  await expect(removeGitHubDidFiles("token")).rejects.toThrow(/still has/i);
});
