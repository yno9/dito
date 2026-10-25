/**
 * Publication-host adapters for a did:vh log, by web location (`https://alice.did.md`,
 * `https://alice.github.io`): the place the identity's own document names.
 *
 * The dashboard never branches on "is this did.md or GitHub" again: it asks
 * `hostForDid(did)` for an IdentityHost and calls the same three verbs
 * (isLive / publish / remove). Each adapter owns its transport:
 *
 *  - did.md  — HTTP API at <username>.did.md (POST one entry / PUT full log / DELETE)
 *  - GitHub  — Octokit Git Data commit of the full log + .nojekyll + did.json,
 *              then GitHub Pages (see github-host.ts)
 *
 * Secrets (GitHub PAT) are passed in as `credential` per call and never
 * stored here. When an adapter needs one and none was supplied it throws
 * CredentialRequiredError so the UI can open the PAT dialog and retry.
 */
import { VhHostingClient, logUrlOf, serializeVhLog, type Ed25519Key, type VhLogEntry } from "../../vh/src/index.ts";
import {
  githubErrorMessage,
  removeGitHubDidFiles,
  updateGitHubLog,
} from "./github-host.ts";

export type HostKind = "http" | "github";

type Entry = VhLogEntry;
export type SignKeyLike = Ed25519Key;

export type PublishArgs = {
  /** The location published to (`https://alice.did.md`). */
  src: string;
  /** Full log including any entry being published now. */
  entries: Entry[];
  message?: string;
  /**
   * append  — did.md POST of the last entry only (key rotation, Docs edit).
   * replace — write the complete log (portability move, GitHub, republish).
   */
  mode?: "append" | "replace";
  /** GitHub PAT. Required for every GitHub write. */
  credential?: string;
};

export type PublishResult = {
  kind: HostKind;
  did: string;
  logUrl: string;
  versionId: string;
  /** False when the public URL is not confirmed live yet (Pages lag). */
  verifiedLive: boolean;
};

export class CredentialRequiredError extends Error {
  readonly hostKind: HostKind;
  constructor(hostKind: HostKind, message?: string) {
    super(message ?? "A GitHub personal access token is required to write to this host.");
    this.name = "CredentialRequiredError";
    this.hostKind = hostKind;
  }
}

export class HostError extends Error {
  readonly hostKind: HostKind;
  constructor(hostKind: HostKind, message: string) {
    super(message);
    this.name = "HostError";
    this.hostKind = hostKind;
  }
}

export interface IdentityHost {
  readonly kind: HostKind;
  /** Short label for the identity card / toasts. */
  readonly label: string;
  /** True when this adapter is the publication location `src` (`https://alice.did.md`). */
  owns(src: string): boolean;
  /** Public DID-log URL of the location. */
  logUrl(src: string): string;
  /** True if the host currently serves the log. */
  isLive(src: string): Promise<boolean>;
  publish(args: PublishArgs): Promise<PublishResult>;
  /**
   * Un-host the DID at this adapter's location. did.md uses a signed
   * DELETE; GitHub deletes only the DID files (never the repository).
   * Throws CredentialRequiredError when a GitHub PAT is missing.
   */
  remove(src: string, did: string, signKey: SignKeyLike, credential?: string): Promise<true>;
}

function hostOfSrc(src: string): string {
  try { return new URL(src).host.toLowerCase(); } catch { return ""; }
}

export function isGitHubSrc(src: string): boolean {
  return /^[A-Za-z0-9-]+\.github\.io$/i.test(hostOfSrc(src));
}

async function fetchOk(url: string, init?: RequestInit): Promise<Response> {
  // Cache-bust with a unique query only. Do NOT set Cache-Control/Pragma
  // request headers: those trigger a CORS preflight and did.md's
  // Access-Control-Allow-Headers rejects them, so isLive always failed
  // after Refresh (found live 2026-09-29). `cache: no-store` is a fetch
  // cache mode and does not need a custom header.
  const busted = `${url}${url.includes("?") ? "&" : "?"}_=${Date.now()}`;
  const response = await fetch(busted, {
    cache: "no-store",
    ...init,
  });
  return response;
}

/**
 * Any host that speaks the did:vh Hosting Protocol (SPEC-vh-hosting.md): did.md, or a
 * third party. Every URL comes from the location, so nothing here knows which server it is.
 */
class HttpHost implements IdentityHost {
  readonly kind = "http" as const;
  readonly label = "web host";
  private readonly client = new VhHostingClient();

  owns(src: string): boolean {
    return !isGitHubSrc(src);
  }

  logUrl(src: string): string {
    return logUrlOf(src);
  }

  async isLive(src: string): Promise<boolean> {
    try {
      return (await this.client.read(src)) !== null;
    } catch {
      return false;
    }
  }

  async publish(args: PublishArgs): Promise<PublishResult> {
    const latest = args.entries[args.entries.length - 1];
    if (!latest?.state?.id || typeof latest.state.id !== "string") {
      throw new HostError(this.kind, "The DID log has no current DID Document.");
    }
    const did = latest.state.id as string;
    try {
      if ((args.mode ?? "append") === "append") await this.client.append(args.src, `${JSON.stringify(latest)}\n`);
      else await this.client.publish(args.src, serializeVhLog(args.entries));
    } catch (error) {
      throw new HostError(this.kind, error instanceof Error ? error.message : `Publication failed.`);
    }
    return { kind: this.kind, did, logUrl: this.logUrl(args.src), versionId: latest.versionId, verifiedLive: true };
  }

  async remove(src: string, did: string, signKey: SignKeyLike, _credential?: string): Promise<true> {
    try {
      // Already gone counts as removed (the location was removed earlier or never published).
      await this.client.remove(src, did, signKey);
    } catch (error) {
      throw new HostError(this.kind, error instanceof Error ? error.message : "Disconnect failed.");
    }
    return true;
  }
}

/** GitHub Pages user site (`https://<login>.github.io`). */
class GitHubHost implements IdentityHost {
  readonly kind = "github" as const;
  readonly label = "github";

  owns(src: string): boolean {
    return isGitHubSrc(src);
  }

  logUrl(src: string): string {
    const host = hostOfSrc(src);
    if (!/^[a-z0-9-]+\.github\.io$/.test(host)) {
      throw new HostError(this.kind, "This identity is not hosted on GitHub Pages.");
    }
    return `https://${host}/.well-known/did.jsonl`;
  }

  async isLive(src: string): Promise<boolean> {
    try {
      return (await fetchOk(this.logUrl(src))).ok;
    } catch {
      return false;
    }
  }

  async publish(args: PublishArgs): Promise<PublishResult> {
    const token = args.credential?.trim();
    if (!token) throw new CredentialRequiredError(this.kind);
    const latest = args.entries[args.entries.length - 1];
    if (!latest?.state?.id || typeof latest.state.id !== "string") {
      throw new HostError(this.kind, "The DID log has no current DID Document.");
    }
    const did = latest.state.id as string;
    try {
      // GitHub has no append verb -- every write is a full-log replace.
      // Initial host / Pages enablement uses publishToGitHub from the
      // host-card flow; Docs/Keys and republish use this lighter path.
      const result = await updateGitHubLog(token, args.entries, args.message);
      return {
        kind: this.kind,
        did: result.did,
        logUrl: result.publicUrl,
        versionId: result.versionId,
        verifiedLive: true,
      };
    } catch (error) {
      if (error instanceof CredentialRequiredError) throw error;
      throw new HostError(this.kind, githubErrorMessage(error));
    }
  }

  /**
   * Un-host by deleting only `.well-known/did.jsonl` and
   * `.well-known/did.json`. The repository and any other Pages content
   * stay -- `<login>.github.io` is the user's site, not just this DID.
   */
  async remove(_src: string, _did: string, _signKey: SignKeyLike, credential?: string): Promise<true> {
    const token = credential?.trim();
    if (!token) throw new CredentialRequiredError(this.kind);
    try {
      await removeGitHubDidFiles(token);
      return true;
    } catch (error) {
      if (error instanceof CredentialRequiredError) throw error;
      throw new HostError(this.kind, githubErrorMessage(error));
    }
  }
}

const httpHost = new HttpHost();
const gitHubHost = new GitHubHost();

export function hostForKind(kind: HostKind): IdentityHost {
  return kind === "github" ? gitHubHost : httpHost;
}

/** The adapter that owns a publication location. */
export function hostForSrc(src: string): IdentityHost {
  if (gitHubHost.owns(src)) return gitHubHost;
  return httpHost;
}
