/**
 * dito CLI: manage a did:webvh identity from a terminal, a script or an
 * agent. Thin shell over packages/wallet's `Identity`.
 *
 * Files:    the public log lives in `--log` (default ./did.jsonl).
 * Secrets:  the mnemonic is NEVER written by this tool. Supply it through
 *           --mnemonic-file, $DITO_MNEMONIC, or (interactive) a prompt.
 *           A GitHub token comes from $GITHUB_TOKEN (or --token-env NAME).
 * Output:   human text by default; --json prints one JSON object (agents).
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { parseArgs } from "node:util";
import { buildDidJson } from "../../wallet/src/github-host.ts";
import { hostForDid } from "../../wallet/src/host.ts";
import { Identity } from "../../wallet/src/identity.ts";
import { didToLogUrl, parseLog, resolveDidWebvh, resolveLog } from "../../webvh/src/index.ts";

export type IO = {
  out: (text: string) => void;
  err: (text: string) => void;
  env: Record<string, string | undefined>;
  /** Interactive secret prompt; undefined when not a TTY. */
  prompt?: (question: string) => Promise<string>;
};

const HELP = `dito -- did:webvh identities from the command line

Usage: dito <command> [options]

  new                       Create an identity (provisional DID) and write the log
  show                      Print the DID, host and DID Document (no secret needed)
  verify [file|url|did]     Validate a log (default: --log); a did:webvh DID is fetched with its witness file
  fetch <did>               Download a published log to --log (public; no secret needed)
  export                    Write .well-known/did.jsonl + did.json from the log (no secret needed)
  export --jwe              Write <scid>.jwe: log + keyring wrapped by the mnemonic (needs the mnemonic)
  publish                   PUT the whole log to the host its DID names (no secret; GitHub hosts need $GITHUB_TOKEN)
  import <scid>.jwe         Restore the log from a .jwe with the mnemonic
  domain <host>             Re-home on your own domain/apex, write .well-known/did.jsonl + did.json
  connect <username>        Host on <username>.did.md   (--domain to change)
  github                    Host on <login>.github.io   (token from $GITHUB_TOKEN)
  rotate                    Rotate the Sign key
  service add <id> <type> <endpoint>
  service remove <id>       Edit DID Document services
  unpublish                 Take the DID down from its host

Options
  --log <file>              DID log (default ./did.jsonl)
  --mnemonic-file <file>    Read the 24-word mnemonic from a file ($DITO_MNEMONIC also works)
  --json                    Machine-readable output
  --api <url>               new: wallet API for the #udi-wallet-issuer service
  --local                   rotate/service: update the log only, never contact the host (use with export)
  --out <dir>               domain/export: output directory (default .)
  --domain <domain>         connect: hosting domain (default did.md)
  --token-env <NAME>        github/rotate/...: env var holding the GitHub token
`;

class UsageError extends Error {}

export async function run(argv: string[], io: IO): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv, allowPositionals: true, strict: true,
      options: {
        log: { type: "string", default: "did.jsonl" },
        "mnemonic-file": { type: "string" },
        json: { type: "boolean", default: false },
        api: { type: "string" },
        domain: { type: "string" },
        out: { type: "string" },
        local: { type: "boolean" },
        jwe: { type: "boolean" },
        "token-env": { type: "string", default: "GITHUB_TOKEN" },
        help: { type: "boolean", short: "h", default: false },
      },
    });
  } catch (error) {
    io.err(`${(error as Error).message}\n\n${HELP}`);
    return 2;
  }
  const { values, positionals } = parsed;
  const [command, ...rest] = positionals;
  const emit = (data: Record<string, unknown>, human: string) => io.out(values.json ? `${JSON.stringify(data)}\n` : `${human}\n`);
  try {
    if (values.help || !command) { io.out(HELP); return command || values.help ? 0 : 2; }
    const logFile = values.log!;
    const readLog = () => {
      if (!existsSync(logFile)) throw new UsageError(`No DID log at ${logFile}. Run \`dito new\` first (or pass --log).`);
      return readFileSync(logFile, "utf8");
    };
    const mnemonic = async () => {
      const fromFile = values["mnemonic-file"] ? readFileSync(values["mnemonic-file"], "utf8") : undefined;
      const value = fromFile ?? io.env.DITO_MNEMONIC ?? (io.prompt ? await io.prompt("Mnemonic (24 words): ") : undefined);
      if (!value?.trim()) throw new UsageError("A mnemonic is required: --mnemonic-file, $DITO_MNEMONIC, or run in a terminal.");
      return value.trim();
    };
    const open = async () => Identity.open({ mnemonic: await mnemonic(), log: readLog() });
    const token = () => io.env[values["token-env"]!];
    const save = (identity: Identity) => { mkdirSync(dirname(logFile), { recursive: true }); writeFileSync(logFile, identity.logText(), { mode: 0o644 }); };
    const summary = (identity: Identity) => ({ did: identity.did, provisional: identity.isProvisional, entries: identity.entries.length, host: identity.isProvisional ? null : identity.host.kind });

    switch (command) {
      case "new": {
        if (existsSync(logFile)) throw new UsageError(`${logFile} already exists; refusing to overwrite.`);
        const { identity, mnemonic: words } = await Identity.create({ api: values.api });
        save(identity);
        emit({ ...summary(identity), log: logFile, mnemonic: words },
          `Created ${identity.did}\nLog written to ${logFile}\n\nMnemonic -- write it down, it is the ONLY way to recover this identity:\n${words}`);
        return 0;
      }
      case "show": {
        const log = parseLog(readLog());
        const resolved = await resolveLog(log);
        const did = resolved.did;
        emit({ did, versionId: resolved.meta.versionId, entries: log.length, deactivated: resolved.meta.deactivated, document: resolved.doc },
          `${did}\nentries: ${log.length}   version: ${resolved.meta.versionId}   deactivated: ${resolved.meta.deactivated}\n${JSON.stringify(resolved.doc, null, 2)}`);
        return 0;
      }
      case "fetch": {
        if (!rest[0]?.startsWith("did:webvh:")) throw new UsageError("Usage: dito fetch <did:webvh:…>");
        if (existsSync(logFile)) throw new UsageError(`${logFile} already exists; refusing to overwrite.`);
        const resolved = await resolveDidWebvh(rest[0]);
        const text = await (await fetch(didToLogUrl(rest[0]), { cache: "no-store" })).text();
        mkdirSync(dirname(logFile), { recursive: true });
        writeFileSync(logFile, text, { mode: 0o644 });
        emit({ did: resolved.did, log: logFile, versionId: resolved.meta.versionId }, `Saved ${resolved.did} to ${logFile}`);
        return 0;
      }
      case "verify": {
        if (rest[0]?.startsWith("did:webvh:")) {
          const resolved = await resolveDidWebvh(rest[0]);
          emit({ ok: true, did: resolved.did, versionId: resolved.meta.versionId }, `OK  ${resolved.did}  (${resolved.meta.versionId})`);
          return 0;
        }
        const source = rest[0] ?? logFile;
        const text = /^https?:\/\//.test(source) ? await (await fetch(source, { cache: "no-store" })).text() : readFileSync(source, "utf8");
        const log = parseLog(text);
        const resolved = await resolveLog(log);
        emit({ ok: true, did: resolved.did, entries: log.length, versionId: resolved.meta.versionId }, `OK  ${resolved.did}  (${log.length} entries, ${resolved.meta.versionId})`);
        return 0;
      }
      case "connect": {
        if (!rest[0]) throw new UsageError("Usage: dito connect <username> [--domain did.md]");
        const identity = await open();
        const result = await identity.connect({ username: rest[0], domain: values.domain });
        save(identity);
        emit({ ...summary(identity), logUrl: result.logUrl, ...(result.cleanupError ? { warning: result.cleanupError.message } : {}) },
          `Published ${identity.did}\n${result.logUrl}${result.cleanupError ? `\nwarning: previous host not cleaned up: ${result.cleanupError.message}` : ""}`);
        return 0;
      }
      case "domain": {
        if (!rest[0]) throw new UsageError("Usage: dito domain <host> [--out <dir>]   e.g. dito domain digitalcommons.jp");
        const identity = await open();
        const moved = await identity.moveToDomain(rest[0]);
        save(identity);
        const out = join(values.out ?? ".", ".well-known");
        mkdirSync(out, { recursive: true });
        writeFileSync(join(out, "did.jsonl"), identity.logText());
        writeFileSync(join(out, "did.json"), moved.didJson);
        emit({ ...summary(identity), didWeb: moved.didWeb, previousDid: moved.previousDid, wrote: out },
          `${moved.did}\n${moved.didWeb}\nWrote did.jsonl and did.json to ${out}/\nServe them at https://${rest[0].toLowerCase()}/.well-known/ (CORS: Access-Control-Allow-Origin: *), then: dito verify ${moved.did}`);
        return 0;
      }
      case "export": {
        if (values.jwe) {
          const { scid, jwe } = await (await open()).exportContainer();
          mkdirSync(values.out ?? ".", { recursive: true });
          const file = join(values.out ?? ".", `${scid}.jwe`);
          writeFileSync(file, jwe, { mode: 0o600 });
          emit({ scid, wrote: file }, `Wrote ${file} (open it with the same mnemonic: dito import ${file})`);
          return 0;
        }
        const text = readLog();
        const log = parseLog(text);
        const resolved = await resolveLog(log);
        const out = join(values.out ?? ".", ".well-known");
        mkdirSync(out, { recursive: true });
        writeFileSync(join(out, "did.jsonl"), text.endsWith("\n") ? text : `${text}\n`);
        writeFileSync(join(out, "did.json"), buildDidJson(resolved.doc, resolved.did));
        emit({ did: resolved.did, versionId: resolved.meta.versionId, wrote: out }, `Wrote did.jsonl and did.json for ${resolved.did} (${resolved.meta.versionId}) to ${out}/`);
        return 0;
      }
      case "publish": {
        // Needs no secret: PUT of the full log, which the host validates itself.
        const entries = parseLog(readLog());
        const did = (await resolveLog(entries)).did;
        const result = await hostForDid(did).publish({ entries: entries as never, mode: "replace", credential: token(), message: `Publish ${entries.at(-1)!.versionId}` });
        // Read it back from the DID's own location and verify, as the protocol asks.
        const live = await resolveDidWebvh(did);
        emit({ did, logUrl: result.logUrl, versionId: live.meta.versionId, verified: live.meta.versionId === entries.at(-1)!.versionId },
          `Published ${did}\n${result.logUrl}\nverified: ${live.meta.versionId}`);
        return 0;
      }
      case "import": {
        if (!rest[0]) throw new UsageError("Usage: dito import <scid>.jwe   (needs the mnemonic)");
        if (existsSync(logFile)) throw new UsageError(`${logFile} already exists; refusing to overwrite.`);
        const identity = await Identity.fromContainer({ jwe: readFileSync(rest[0], "utf8").trim(), mnemonic: await mnemonic() });
        save(identity);
        emit({ ...summary(identity), log: logFile }, `Restored ${identity.did}\nLog written to ${logFile}`);
        return 0;
      }
      case "github": {
        const value = token();
        if (!value) throw new UsageError(`Set ${values["token-env"]} to a GitHub classic PAT with the repo scope.`);
        const identity = await open();
        const result = await identity.hostOnGitHub({ token: value, onProgress: step => { if (!values.json) io.err(`  ${step}\n`); } });
        save(identity);
        emit({ ...summary(identity), publicUrl: result.publicUrl, verifiedLive: result.verifiedLive },
          `Published ${identity.did}\n${result.publicUrl}${result.verifiedLive ? "" : "\n(not confirmed live yet -- GitHub Pages can take a few minutes)"}`);
        return 0;
      }
      case "rotate":
      case "service": {
        const identity = await open();
        let edit: ((state: Record<string, any>) => Record<string, any>) | undefined;
        if (command === "service") {
          const [action, id, type, endpoint] = rest;
          if (action === "add" && id && type && endpoint) {
            edit = state => ({ ...state, service: [...(state.service ?? []).filter((s: any) => s.id !== id), { id, type, serviceEndpoint: endpoint }] });
          } else if (action === "remove" && id) {
            edit = state => ({ ...state, service: (state.service ?? []).filter((s: any) => s.id !== id) });
          } else throw new UsageError("Usage: dito service add <id> <type> <endpoint> | dito service remove <id>");
        }
        if (identity.isProvisional || values.local) {
          // No host yet, or a self-hosted domain (`--local`): the change stays in the log; `dito export` writes the files to serve.
          await identity.commit(await identity.prepareUpdate(edit ? edit(JSON.parse(JSON.stringify(identity.state))) : identity.state));
        } else {
          await identity.publishUpdate(edit, { credential: token() });
        }
        save(identity);
        emit({ ...summary(identity) }, `Updated ${identity.did} (${identity.entries.length} entries)`);
        return 0;
      }
      case "unpublish": {
        const identity = await open();
        await identity.unpublish({ credential: token() });
        emit({ ...summary(identity), unpublished: true }, `Removed ${identity.did} from its host.`);
        return 0;
      }
      default:
        throw new UsageError(`Unknown command "${command}".\n\n${HELP}`);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    io.err(values.json ? `${JSON.stringify({ error: message })}\n` : `error: ${message}\n`);
    return error instanceof UsageError ? 2 : 1;
  }
}
