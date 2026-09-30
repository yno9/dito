/**
 * Host a portable did:webvh log on the user's own GitHub Pages site.
 *
 * Pure location helpers plus thin Octokit wrappers -- no UI. The browser
 * talks only to api.github.com and the published *.github.io URL; did.md
 * servers are never involved. The PAT lives in a local variable only and is
 * never written to storage.
 *
 * Pre-push validation reuses server/host/webvh-core.ts (no Node imports) so
 * a log that would be rejected by the did.md host is never written to GitHub
 * either.
 */
import { Octokit } from "@octokit/core";
import {
  mirrorDocument,
  parseJsonl,
  serialise,
  validateLogAt,
  type Entry,
  type Obj,
} from "./webvh-core.ts";

export type GitHubLocation = {
  login: string;
  repo: string;
  /** DID domain segment: `<login>.github.io` (always lowercase). */
  domain: string;
  /** No path segments in MVP (user site only). */
  segments: string[];
  /** Public log URL matching didWebvhLogUrl / didToLogUrl. */
  publicUrl: string;
  /** Repo path of the DID log. */
  contentsPath: string;
  /** Repo path of the did:web mirror. */
  didJsonPath: string;
  /** Repo path of the Jekyll disable marker. */
  nojekyllPath: string;
  /** Public URL of the did:web mirror. */
  didJsonPublicUrl: string;
};

export type PublishFile = { path: string; content: string };

export type PublishProgress = (step: string) => void;

export type PublishResult = {
  login: string;
  repo: string;
  domain: string;
  did: string;
  publicUrl: string;
  didJsonPublicUrl: string;
  versionId: string;
  pagesStatus: string;
  /** False when Pages has not started serving the log yet (offer Recheck). */
  verifiedLive: boolean;
};

const USER_SITE_REPO_SUFFIX = ".github.io";

/** Lowercase login -- did:webvh domains are case-insensitive DNS labels. */
export function normalizeLogin(login: string): string {
  const trimmed = typeof login === "string" ? login.trim() : "";
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}[A-Za-z0-9])?$/.test(trimmed)) {
    throw new Error("GitHub login is not a valid account name.");
  }
  return trimmed.toLowerCase();
}

/**
 * User-site location. MVP fixes the repo name to `<login>.github.io`, so
 * every helper that takes a repo defaults to that.
 */
export function githubDidLocation(login: string, repo?: string): GitHubLocation {
  const user = normalizeLogin(login);
  const name = (repo ?? `${user}${USER_SITE_REPO_SUFFIX}`).trim();
  if (!name) throw new Error("Repository name is required.");
  if (!/^[A-Za-z0-9_.-]+$/.test(name)) throw new Error("Repository name is invalid.");
  const domain = `${user}${USER_SITE_REPO_SUFFIX}`;
  return {
    login: user,
    repo: name,
    domain,
    segments: [],
    publicUrl: `https://${domain}/.well-known/did.jsonl`,
    contentsPath: ".well-known/did.jsonl",
    didJsonPath: ".well-known/did.json",
    nojekyllPath: ".nojekyll",
    didJsonPublicUrl: `https://${domain}/.well-known/did.json`,
  };
}

/** Public DID-log URL for a user site -- matches didWebvhLogUrl exactly. */
export function githubLogUrl(login: string, repo?: string): string {
  return githubDidLocation(login, repo).publicUrl;
}

/** Base64 for the Git Data / Contents APIs (UTF-8 safe). */
export function toBase64Utf8(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** Inverse of toBase64Utf8. */
export function fromBase64Utf8(value: string): string {
  const binary = atob(value.replace(/\s/g, ""));
  const bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

/** Map an Octokit/HTTP error onto a message the user can act on. */
export function githubErrorMessage(error: unknown): string {
  const status = (error as { status?: number } | null)?.status;
  const raw = error instanceof Error
    ? error.message
    : (error as { message?: string } | null)?.message ?? String(error);
  if (status === 401) return "GitHub rejected this token. Generate a new classic PAT with the repo scope and try again.";
  if (status === 403) {
    if (/rate limit/i.test(raw)) return "GitHub rate limit reached. Wait a few minutes and try again.";
    return "GitHub refused this action (missing permission or private-repo Pages restriction). Check the token's repo scope, or make `<login>.github.io` public if it is private on a Free plan.";
  }
  if (status === 404) return "Repository not found or this token cannot see it.";
  if (status === 409 || status === 422) return "GitHub reported a conflicting update. Try Publish again.";
  return raw || `GitHub request failed (${status ?? "network error"}).`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function makeOctokit(token: string): Octokit {
  return new Octokit({ auth: token });
}

/** GET /user -- returns the account login this token belongs to. */
export async function verifyToken(token: string): Promise<{ login: string }> {
  const octokit = makeOctokit(token);
  const response = await octokit.request("GET /user");
  const login = response.data?.login;
  if (typeof login !== "string" || !login) throw new Error("GitHub did not return an account login for this token.");
  return { login: normalizeLogin(login) };
}

export type RepoInfo = { defaultBranch: string; private: boolean; htmlUrl: string };

/** GET or auto-create `<login>.github.io` (always public when created). */
export async function ensureRepo(token: string, location: GitHubLocation): Promise<RepoInfo> {
  const octokit = makeOctokit(token);
  try {
    const existing = await octokit.request("GET /repos/{owner}/{repo}", {
      owner: location.login,
      repo: location.repo,
    });
    return {
      defaultBranch: existing.data?.default_branch || "main",
      private: Boolean(existing.data?.private),
      htmlUrl: existing.data?.html_url ?? `https://github.com/${location.login}/${location.repo}`,
    };
  } catch (error) {
    if ((error as { status?: number }).status !== 404) throw error;
  }
  const created = await octokit.request("POST /user/repos", {
    name: location.repo,
    private: false,
    auto_init: true,
  });
  return {
    defaultBranch: created.data?.default_branch || "main",
    private: false,
    htmlUrl: created.data?.html_url ?? `https://github.com/${location.login}/${location.repo}`,
  };
}

async function getBranchSha(octokit: Octokit, location: GitHubLocation, branch: string): Promise<{ sha: string; ref: string }> {
  const response = await octokit.request("GET /repos/{owner}/{repo}/git/ref/{ref}", {
    owner: location.login,
    repo: location.repo,
    ref: `heads/${branch}`,
  });
  const sha = response.data?.object?.sha;
  if (typeof sha !== "string" || !sha) throw new Error("GitHub returned no branch commit SHA.");
  return { sha, ref: `heads/${branch}` };
}

async function getFileSha(octokit: Octokit, location: GitHubLocation, path: string): Promise<string | null> {
  try {
    const response = await octokit.request("GET /repos/{owner}/{repo}/contents/{path}", {
      owner: location.login,
      repo: location.repo,
      path,
    });
    const data = response.data;
    if (isRecord(data) && typeof data.sha === "string") return data.sha;
    return null;
  } catch (error) {
    if ((error as { status?: number }).status === 404) return null;
    throw error;
  }
}

/**
 * Write every file in one Git Data commit so did.jsonl and did.json never
 * disagree mid-publish. A ref conflict (409/422) is retried once after
 * re-reading HEAD; if the Data API itself is unavailable the Contents API
 * writes only the listed paths as a last resort.
 */
export async function commitFiles(
  token: string,
  location: GitHubLocation,
  branch: string,
  files: PublishFile[],
  message: string,
): Promise<{ commitSha: string; retried: boolean }> {
  const octokit = makeOctokit(token);
  const attemptDataApi = async () => {
    const head = await getBranchSha(octokit, location, branch);
    const tree: Array<{ path: string; mode: "100644"; type: "blob"; sha: string }> = [];
    for (const file of files) {
      const blob = await octokit.request("POST /repos/{owner}/{repo}/git/blobs", {
        owner: location.login,
        repo: location.repo,
        content: toBase64Utf8(file.content),
        encoding: "base64",
      });
      const sha = blob.data?.sha;
      if (typeof sha !== "string" || !sha) throw new Error("GitHub returned no blob SHA.");
      tree.push({ path: file.path, mode: "100644", type: "blob", sha });
    }
    const created = await octokit.request("POST /repos/{owner}/{repo}/git/trees", {
      owner: location.login,
      repo: location.repo,
      base_tree: head.sha,
      tree,
    });
    const treeSha = created.data?.sha;
    if (typeof treeSha !== "string" || !treeSha) throw new Error("GitHub returned no tree SHA.");
    const commit = await octokit.request("POST /repos/{owner}/{repo}/git/commits", {
      owner: location.login,
      repo: location.repo,
      message,
      tree: treeSha,
      parents: [head.sha],
    });
    const commitSha = commit.data?.sha;
    if (typeof commitSha !== "string" || !commitSha) throw new Error("GitHub returned no commit SHA.");
    await octokit.request("PATCH /repos/{owner}/{repo}/git/refs/{ref}", {
      owner: location.login,
      repo: location.repo,
      ref: head.ref,
      sha: commitSha,
    });
    return commitSha;
  };

  try {
    return { commitSha: await attemptDataApi(), retried: false };
  } catch (error) {
    const status = (error as { status?: number }).status;
    const conflict = status === 409 || status === 422;
    if (!conflict && status !== undefined && status < 500) throw error;
    try {
      return { commitSha: await attemptDataApi(), retried: true };
    } catch (retryError) {
      const retryStatus = (retryError as { status?: number }).status;
      const retryConflict = retryStatus === 409 || retryStatus === 422;
      if (!retryConflict && retryStatus !== undefined && retryStatus < 500) throw retryError;
    }
  }

  let lastSha = "";
  for (const file of files) {
    const sha = await getFileSha(octokit, location, file.path);
    const response = await octokit.request("PUT /repos/{owner}/{repo}/contents/{path}", {
      owner: location.login,
      repo: location.repo,
      path: file.path,
      message,
      content: toBase64Utf8(file.content),
      ...(sha ? { sha } : {}),
    });
    const commitSha = response.data?.commit?.sha;
    if (typeof commitSha === "string" && commitSha) lastSha = commitSha;
  }
  if (!lastSha) throw new Error("GitHub accepted no file updates.");
  return { commitSha: lastSha, retried: true };
}

/** Enable GitHub Pages on the default branch root (no-op if already on). */
export type PagesInfo = {
  created: boolean;
  /** "legacy" (branch + Jekyll) or "workflow" (GitHub Actions deploy-pages). */
  buildType: "legacy" | "workflow" | "unknown";
  status: string;
  htmlUrl?: string;
};

/**
 * Enable GitHub Pages on the default branch root (no-op if already on).
 * Also reports whether the site is built by the classic branch pipeline
 * (`legacy`) or by GitHub Actions (`workflow`) -- the two expose different
 * build-status APIs, and waiting on the wrong one is what stalls Publish.
 */
export async function ensurePages(token: string, location: GitHubLocation, defaultBranch: string): Promise<PagesInfo> {
  const octokit = makeOctokit(token);
  const readInfo = async (created: boolean): Promise<PagesInfo> => {
    try {
      const response = await octokit.request("GET /repos/{owner}/{repo}/pages", {
        owner: location.login,
        repo: location.repo,
      });
      const data = response.data as { build_type?: string; status?: string; html_url?: string } | undefined;
      const rawType = data?.build_type;
      const buildType: PagesInfo["buildType"] = rawType === "workflow" || rawType === "legacy" ? rawType : "unknown";
      return { created, buildType, status: data?.status ?? "unknown", htmlUrl: data?.html_url };
    } catch {
      return { created, buildType: "unknown", status: "unknown" };
    }
  };
  try {
    await octokit.request("GET /repos/{owner}/{repo}/pages", {
      owner: location.login,
      repo: location.repo,
    });
    return readInfo(false);
  } catch (error) {
    if ((error as { status?: number }).status !== 404) throw error;
  }
  try {
    await octokit.request("POST /repos/{owner}/{repo}/pages", {
      owner: location.login,
      repo: location.repo,
      source: { branch: defaultBranch, path: "/" },
    });
    return readInfo(true);
  } catch (error) {
    const status = (error as { status?: number }).status;
    if (status === 403 || status === 422) {
      throw new Error(
        "GitHub Free plans cannot publish Pages from a private repository. Make `<login>.github.io` public in the repository settings, then press Recheck.",
      );
    }
    throw error;
  }
}

export function pagesErrorMessage(status: string | undefined, error?: string): string {
  if (status === "errored") return `GitHub Pages build failed${error ? `: ${error}` : ""}. Check the repository's Pages settings, then press Recheck.`;
  return `GitHub Pages build is ${status || "unknown"}. Wait a few minutes and press Recheck.`;
}

/**
 * Wait until GitHub Pages reports a successful build.
 *
 * Two pipelines exist and they do **not** share a status endpoint:
 *  - `legacy`   (Deploy from a branch): `GET .../pages/builds/latest`
 *  - `workflow` (GitHub Actions + actions/deploy-pages): that endpoint is
 *    stale/empty; the live `GET .../pages` `status` (or the public URL) is
 *    what actually moves. Waiting on builds/latest here is what left Publish
 *    stuck on "Wait for Pages build" while the Actions deploy had already
 *    reported success (found live 2026-09-29).
 *
 * Returns `{ status, buildType, inconclusive }`. `inconclusive: true` means
 * "do not treat this as a hard failure -- continue to waitForPublish".
 */
export async function waitForPagesBuild(
  token: string,
  location: GitHubLocation,
  options: { intervalMs?: number; timeoutMs?: number; signal?: AbortSignal; buildType?: PagesInfo["buildType"] } = {},
): Promise<{ status: string; buildType: PagesInfo["buildType"]; inconclusive: boolean }> {
  const intervalMs = options.intervalMs ?? 4000;
  const timeoutMs = options.timeoutMs ?? 180_000;
  const octokit = makeOctokit(token);
  const deadline = Date.now() + timeoutMs;
  let buildType = options.buildType ?? "unknown";
  let last = { status: "pending" as string };

  const readPagesResource = async () => {
    const response = await octokit.request("GET /repos/{owner}/{repo}/pages", {
      owner: location.login,
      repo: location.repo,
    });
    const data = response.data as { build_type?: string; status?: string } | undefined;
    if (data?.build_type === "workflow" || data?.build_type === "legacy") buildType = data.build_type;
    return data?.status ?? "unknown";
  };

  for (;;) {
    if (options.signal?.aborted) throw new Error("Canceled.");
    try {
      if (buildType === "unknown") {
        try {
          last = { status: await readPagesResource() };
        } catch (error) {
          if ((error as { status?: number }).status !== 404) throw error;
          last = { status: "unknown" };
        }
      }

      if (buildType === "workflow") {
        // Actions deploys: trust GET /pages.status, never builds/latest.
        last = { status: await readPagesResource() };
        if (last.status === "built") return { status: "built", buildType, inconclusive: false };
        if (last.status === "errored") {
          throw new Error(pagesErrorMessage("errored", "GitHub Actions Pages deployment reported an error"));
        }
        // Still building -- keep polling, but a timeout is inconclusive
        // (the Actions run may have finished without flipping this field).
      } else {
        // Legacy branch build (or unknown): builds/latest is the source of
        // truth. 404 = no build yet. Any other API error is real.
        try {
          const response = await octokit.request("GET /repos/{owner}/{repo}/pages/builds/latest", {
            owner: location.login,
            repo: location.repo,
          });
          last = { status: response.data?.status ?? "unknown" };
          if (last.status === "built") return { status: "built", buildType, inconclusive: false };
          if (last.status === "errored") {
            const errorText = (response.data as { error?: { message?: string } } | undefined)?.error?.message;
            throw new Error(pagesErrorMessage(last.status, errorText));
          }
        } catch (error) {
          const status = (error as { status?: number }).status;
          if (error instanceof Error && /Pages build failed/i.test(error.message)) throw error;
          if (status !== undefined && status !== 404) throw error;
        }
      }
    } catch (error) {
      if (error instanceof Error && (/Pages build failed/i.test(error.message) || /cannot publish Pages/i.test(error.message) || /Canceled/.test(error.message))) {
        throw error;
      }
      // Unexpected read error: keep polling until the deadline rather than
      // aborting a publish that is probably still going.
    }
    if (Date.now() >= deadline) {
      // Never hard-fail a workflow-based site on this endpoint -- the public
      // URL check is the acceptance gate. For legacy, a stuck build is still
      // worth reporting, but as inconclusive so waitForPublish can run.
      return {
        status: last.status,
        buildType,
        inconclusive: true,
      };
    }
    await new Promise(resolve => setTimeout(resolve, intervalMs));
  }
}

/**
 * Fetch the published log until its last versionId matches. Pages is
 * expected to serve Access-Control-Allow-Origin: *; if the browser blocks
 * the read, the caller should treat that as "maybe published" and show the
 * public URL rather than a hard failure.
 */
export async function waitForPublish(
  publicUrl: string,
  expectedLastVersionId: string,
  options: { intervalMs?: number; timeoutMs?: number; signal?: AbortSignal; fetchImpl?: typeof fetch } = {},
): Promise<{ ok: true; versionId: string; body: string }> {
  const intervalMs = options.intervalMs ?? 4000;
  const timeoutMs = options.timeoutMs ?? 180_000;
  const doFetch = options.fetchImpl ?? fetch;
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (options.signal?.aborted) throw new Error("Canceled.");
    try {
      const response = await doFetch(publicUrl, { cache: "no-store" });
      if (response.ok) {
        const body = await response.text();
        const lines = body.split("\n").map(line => line.trim()).filter(Boolean);
        const last = lines.length ? JSON.parse(lines[lines.length - 1]!) : null;
        const versionId = last?.versionId;
        if (typeof versionId === "string" && versionId === expectedLastVersionId) {
          return { ok: true, versionId, body };
        }
      }
    } catch {
      // Network / CORS -- keep polling; the caller can also offer Recheck.
    }
    if (Date.now() >= deadline) {
      throw new Error(
        "The GitHub Pages site is not serving the published log yet. " +
          "If this repository deploys Pages with GitHub Actions, the workflow's uploaded artifact must include `.well-known/` and `.nojekyll` (a site build that only ships an app bundle will never serve did.jsonl). " +
          "Otherwise it can still take a few minutes — press Recheck.",
      );
    }
    await new Promise(resolve => setTimeout(resolve, intervalMs));
  }
}

/**
 * Same checks the did.md host runs before every write, pointed at the
 * GitHub publication URL. Never throws into a network call -- the caller
 * must run this before any Octokit write.
 */
export async function validateBeforePublish(entries: Entry[], expectedLogUrl: string): Promise<Entry> {
  if (!Array.isArray(entries) || !entries.length) throw new Error("There is no DID log to publish.");
  const result = await validateLogAt(entries, [], expectedLogUrl);
  return result.latest;
}

/** did:web mirror of the final state. `hostedResources: false` omits
 *  #files/#whois, which only exist on did.md hosts. */
export function buildDidJson(state: Obj, webvhDid: string): string {
  return `${JSON.stringify(mirrorDocument(state, webvhDid, { hostedResources: false }))}\n`;
}

/**
 * The three files published in one commit:
 *  1. .well-known/did.jsonl  -- full log (history + portability entry)
 *  2. .nojekyll              -- empty; Jekyll otherwise drops .well-known
 *  3. .well-known/did.json   -- did:web mirror of the final state
 *
 * `.nojekyll` is required on GitHub Pages: without it Jekyll strips
 * dot-directories and `.well-known/did.jsonl` is never served. The official
 * did:webvh tutorial does not mention this; confirmed against real Pages
 * builds (2026-09).
 */
export function buildPublishFiles(entries: Entry[], location: GitHubLocation): PublishFile[] {
  const latest = entries[entries.length - 1];
  if (!latest || !isRecord(latest.state) || typeof latest.state.id !== "string") {
    throw new Error("The DID log has no current DID Document.");
  }
  const didJsonl = serialise(entries);
  const didJson = buildDidJson(latest.state as Obj, latest.state.id as string);
  return [
    { path: location.contentsPath, content: didJsonl },
    { path: location.nojekyllPath, content: "" },
    { path: location.didJsonPath, content: didJson },
  ];
}

/** Re-parse a published log and confirm it still validates + matches. */
export async function verifyPublishedLog(body: string, expectedLogUrl: string, expectedVersionId: string): Promise<void> {
  const entries = parseJsonl(body);
  const latest = await validateBeforePublish(entries, expectedLogUrl);
  if (latest.versionId !== expectedVersionId) {
    throw new Error("The published DID log's last version does not match what was uploaded.");
  }
}

export type PublishArgs = {
  token: string;
  entries: Entry[];
  message?: string;
  onProgress?: PublishProgress;
  signal?: AbortSignal;
  /** Optional overrides for tests. */
  fetchImpl?: typeof fetch;
  intervalMs?: number;
  timeoutMs?: number;
};

/**
 * Full MVP publish: verify token → ensure repo → validate locally →
 * commit files → enable Pages → wait for build → wait for publish →
 * re-verify the live log and did.json mirror.
 *
 * The token is used only on the Octokit instances created here and is never
 * returned or stored.
 */
export async function publishToGitHub(args: PublishArgs): Promise<PublishResult> {
  const progress = args.onProgress ?? (() => {});
  const entries = args.entries.map(entry => JSON.parse(JSON.stringify(entry)) as Entry);
  // Token check is a read; everything after local validation may write.
  // A log that fails validateLogAt must never create a repo or touch files.
  progress("verify-token");
  const { login } = await verifyToken(args.token);
  const location = githubDidLocation(login);
  progress("validate");
  const latest = await validateBeforePublish(entries, location.publicUrl);
  const versionId = latest.versionId;
  const files = buildPublishFiles(entries, location);
  progress("ensure-repo");
  const repo = await ensureRepo(args.token, location);
  progress("commit");
  await commitFiles(args.token, location, repo.defaultBranch, files, args.message ?? `Publish did:webvh ${versionId}`);
  progress("enable-pages");
  const pages = await ensurePages(args.token, location, repo.defaultBranch);
  progress("wait-build");
  // Build wait is advisory for workflow-based Pages (Actions deploy-pages):
  // that pipeline does not update /pages/builds/latest, and GET /pages
  // status often stays stale too -- polling it for minutes is what made
  // Publish look stuck at step 6 (found live 2026-09-29). Skip straight
  // to the public-URL check, which is the acceptance gate either way.
  let build: { status: string; buildType: PagesInfo["buildType"]; inconclusive: boolean };
  if (pages.buildType === "workflow") {
    build = { status: pages.status || "unknown", buildType: "workflow", inconclusive: true };
  } else {
    try {
      build = await waitForPagesBuild(args.token, location, {
        intervalMs: args.intervalMs,
        timeoutMs: args.timeoutMs,
        signal: args.signal,
        buildType: pages.buildType,
      });
    } catch (error) {
      if (error instanceof Error && /Pages build failed/i.test(error.message) && pages.buildType !== "workflow") {
        throw error;
      }
      build = { status: pages.status || "unknown", buildType: pages.buildType, inconclusive: true };
    }
  }
  progress("wait-publish");
  let publishedBody: string | null = null;
  let verifiedLive = false;
  try {
    const published = await waitForPublish(location.publicUrl, versionId, {
      intervalMs: args.intervalMs,
      timeoutMs: args.timeoutMs,
      signal: args.signal,
      fetchImpl: args.fetchImpl,
    });
    publishedBody = published.body;
    progress("verify-published");
    await verifyPublishedLog(published.body, location.publicUrl, versionId);
    verifiedLive = true;
  } catch (error) {
    // CORS / slow Pages -- still return a usable result with the public URL;
    // the UI offers Recheck rather than treating the publish as failed.
    if (error instanceof Error && /not serving the published log yet/i.test(error.message)) {
      return {
        login: location.login,
        repo: location.repo,
        domain: location.domain,
        did: latest.state.id as string,
        publicUrl: location.publicUrl,
        didJsonPublicUrl: location.didJsonPublicUrl,
        versionId,
        pagesStatus: build.status,
        verifiedLive: false,
      };
    }
    throw error;
  }
  if (publishedBody !== null) {
    // Independent did.json check: the live mirror must match a fresh render.
    progress("verify-mirror");
    const mirrorUrl = location.didJsonPublicUrl;
    try {
      const mirrorResponse = await (args.fetchImpl ?? fetch)(mirrorUrl, { cache: "no-store" });
      if (mirrorResponse.ok) {
        const expected = buildDidJson(latest.state as Obj, latest.state.id as string);
        const actual = await mirrorResponse.text();
        if (actual !== expected) throw new Error("The published did.json does not match the DID log's final state.");
      }
    } catch (error) {
      if (error instanceof Error && /does not match/.test(error.message)) throw error;
      // Network/CORS on the mirror -- already validated the log itself.
    }
  }
  progress("done");
  return {
    login: location.login,
    repo: location.repo,
    domain: location.domain,
    did: latest.state.id as string,
    publicUrl: location.publicUrl,
    didJsonPublicUrl: location.didJsonPublicUrl,
    versionId,
    pagesStatus: build.status,
    verifiedLive,
  };
}

/**
 * Append one entry to an already-published log (2nd+ publish). The caller
 * supplies the existing remote entries plus the new one; the same
 * validate→commit→Pages pipeline runs. Used by the host-row "Update" action.
 */
export async function republishToGitHub(args: PublishArgs): Promise<PublishResult> {
  return publishToGitHub(args);
}

/**
 * Write an updated full log (and its did.json mirror) to the user site
 * after the initial publish. Used by Docs add/remove and Keys rotation when
 * the identity already lives on `<login>.github.io`. Requires a PAT for the
 * commit -- the caller prompts; nothing is stored here.
 */
export async function updateGitHubLog(
  token: string,
  entries: Entry[],
  message?: string,
): Promise<{ versionId: string; publicUrl: string; domain: string; did: string }> {
  const { login } = await verifyToken(token);
  const location = githubDidLocation(login);
  const latest = await validateBeforePublish(entries, location.publicUrl);
  const files = buildPublishFiles(entries, location);
  const repo = await ensureRepo(token, location);
  await commitFiles(token, location, repo.defaultBranch, files, message ?? `Update did:webvh ${latest.versionId}`);
  return {
    versionId: latest.versionId,
    publicUrl: location.publicUrl,
    domain: location.domain,
    did: latest.state.id as string,
  };
}

/**
 * Un-host a DID by deleting only the published DID files from the user
 * site -- the repository itself (and any other Pages content) stays.
 * This is the GitHub equivalent of did.md's DELETE: the DID stops
 * resolving, without destroying `<login>.github.io`.
 *
 * Removes `.well-known/did.jsonl` and `.well-known/did.json` in one Git
 * Data commit. `.nojekyll` is left in place (harmless). Missing files are
 * already-gone success.
 */
export async function removeGitHubDidFiles(
  token: string,
  options: { message?: string } = {},
): Promise<{ removed: string[]; commitSha: string | null }> {
  const { login } = await verifyToken(token);
  const location = githubDidLocation(login);
  const repo = await ensureRepo(token, location);
  const octokit = makeOctokit(token);
  const paths = [location.contentsPath, location.didJsonPath];

  // Already-gone is success.
  const present: Array<{ path: string; sha: string }> = [];
  for (const path of paths) {
    const sha = await getFileSha(octokit, location, path);
    if (sha) present.push({ path, sha });
  }
  if (!present.length) return { removed: [], commitSha: null };

  // Contents API DELETE is the reliable single-file delete. Git Data
  // `sha: null` in a tree looked like it worked (returned a commit) while
  // leaving every file in place on main (found live 2026-09-29: UI said
  // "removed", https://github.com/.../tree/main/.well-known still listed
  // did.jsonl). Do not use tree-based deletion here.
  const removed: string[] = [];
  let lastSha: string | null = null;
  for (const file of present) {
    let sha = file.sha;
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const response = await octokit.request("DELETE /repos/{owner}/{repo}/contents/{path}", {
          owner: location.login,
          repo: location.repo,
          path: file.path,
          message: options.message ?? `Remove ${file.path}`,
          sha,
          branch: repo.defaultBranch,
        });
        const commitSha = response.data?.commit?.sha;
        if (typeof commitSha === "string" && commitSha) lastSha = commitSha;
        removed.push(file.path);
        break;
      } catch (error) {
        const status = (error as { status?: number }).status;
        if (status === 404) {
          // Already deleted by a concurrent push.
          removed.push(file.path);
          break;
        }
        // 409/422: stale blob sha -- re-read once and retry.
        if ((status === 409 || status === 422) && attempt === 0) {
          const fresh = await getFileSha(octokit, location, file.path);
          if (!fresh) {
            removed.push(file.path);
            break;
          }
          sha = fresh;
          continue;
        }
        throw error;
      }
    }
  }

  // Verify: a "successful" response that left the blob behind must not
  // report success to the UI.
  const leftover: string[] = [];
  for (const file of present) {
    const stillThere = await getFileSha(octokit, location, file.path);
    if (stillThere) leftover.push(file.path);
  }
  if (leftover.length) {
    throw new Error(
      `GitHub still has ${leftover.join(", ")} after delete. Check branch protection or try again.`,
    );
  }
  return { removed, commitSha: lastSha };
}
