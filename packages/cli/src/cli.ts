/**
 * dito CLI: manage a did:vh identity from a terminal, a script or an
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
import { Identity } from "../../wallet/src/identity.ts";
import { VhHostingClient, locationsOf, parseVhDid, parseVhLog, resolveVhLog, serializeVhLog, type VhLogEntry } from "../../vh/src/index.ts";
import { FileVersionMemory, versionMemoryPath } from "./version-memory.ts";

export type IO = {
  out: (text: string) => void;
  err: (text: string) => void;
  env: Record<string, string | undefined>;
  /** Interactive secret prompt; undefined when not a TTY. */
  prompt?: (question: string) => Promise<string>;
};

const HELP = `dito -- did:vh identities from the command line

Usage: dito <command> [options]

  new                       Create an identity (a did:vh DID, no host yet) and write the log
  show                      Print the DID, its locations and DID Document (no secret needed)
  verify [file|url|did]     Validate a log (default: --log); a did:vh DID is fetched from --watcher or --src
  fetch <did>               Download a published log to --log (public; no secret needed)
  forget <did>              Forget the newest version of a DID that verify/fetch remember (see below)
  export                    Write .well-known/did.jsonl + did.json from the log (no secret needed)
  export --jwe              Write <scid>.jwe: log + keyring wrapped by the mnemonic (needs the mnemonic)
  publish                   PUT the whole log to the location its document names (no secret needed)
  import <scid>.jwe         Restore the log from a .jwe with the mnemonic
  domain <host>             Name your own domain/apex as the location, write .well-known/did.jsonl + did.json
  connect <username>        Host on <username>.did.md   (--domain to change)
  github                    Host on <login>.github.io   (token from $GITHUB_TOKEN)
  rotate                    Rotate the Sign key
  service add <id> <type> <endpoint>
  service remove <id>       Edit DID Document services
  unpublish                 Take the log down from its host (this does not deactivate the DID)

Options
  --log <file>              DID log (default ./did.jsonl)
  --mnemonic-file <file>    Read the 24-word mnemonic from a file ($DITO_MNEMONIC also works)
  --json                    Machine-readable output
  --api <url>               new: wallet API for the #wallet service
  --local                   rotate/service: update the log only, never contact the host (use with export)
  --out <dir>               domain/export: output directory (default .)
  --domain <domain>         connect: hosting domain (default did.md)
  --token-env <NAME>        github: env var holding the GitHub token
  --no-memory               verify/fetch <did>: do not read or write the version memory
  --watcher <origin>        verify/fetch <did>: a host serving GET /log?scid= (a did:vh DID names no location)
  --src <location>          verify/fetch <did>: the web location of the log (https://alice.did.md)

A did:vh DID names no host. \`connect <username>\` is one update entry that makes the document name its place; the DID
does not change, and moving later is another entry. The log of someone else's DID is found with --watcher or --src.

Version memory
  verify <did> and fetch <did> remember the newest version they have seen of each DID, in
  $XDG_STATE_HOME/dito/versions.json (default ~/.local/state/dito/versions.json), and refuse a log that is
  older than that, or that forks it: a host or cache serving a copy from before a key rotation verifies fine
  on its own. The cost: a rollback you meant to make (a host restored from a backup, a log recovered from an
  old copy) is refused too, until you run \`dito forget <did>\` (or check once with --no-memory).
`;

class UsageError extends Error {}

const isVhDid = (value: unknown): value is string => typeof value === "string" && value.startsWith("did:vh:");

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
        "no-memory": { type: "boolean" },
        src: { type: "string" },
        watcher: { type: "string" },
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
    const memory = () => values["no-memory"] ? undefined : new FileVersionMemory(versionMemoryPath(io.env));
    const client = new VhHostingClient();
    const save = (identity: Identity) => { mkdirSync(dirname(logFile), { recursive: true }); writeFileSync(logFile, identity.logText(), { mode: 0o644 }); };
    const summary = (identity: Identity) => ({ did: identity.did, method: "did:vh", provisional: identity.isProvisional, entries: identity.entries.length, locations: identity.locations.map(location => location.src) });

    /** Where the log of a did:vh DID is fetched from, as the user said. */
    const fetchLogFor = async (did: string): Promise<string> => {
      const { scid } = parseVhDid(did);
      let text: string | null;
      if (values.src) text = await client.read(values.src);
      else if (values.watcher) text = await client.readByScid(values.watcher, scid);
      else throw new UsageError("A did:vh DID names no location: say where its log is, with --watcher <origin> (a host serving /log?scid=) or --src <location>.");
      if (text === null) throw new Error("No DID log found there.");
      return text;
    };
    /** Verifies the log against the version memory; a refusal comes with the way out. */
    const resolveRemembered = async (did: string, log: VhLogEntry[]) => {
      try { return await resolveVhLog(did, log, { memory: memory() }); }
      catch (error) {
        const name = (error as Error).name;
        if (name === "StaleLogError" || name === "ForkedLogError") {
          throw new Error(`${(error as Error).message} ${name === "StaleLogError" ? "This copy is older than one verified before." : "This log forks the one verified before."} If that is expected (a restored host, a recovered log), run \`dito forget ${did}\` or use --no-memory.`);
        }
        throw error;
      }
    };

    switch (command) {
      case "new": {
        if (existsSync(logFile)) throw new UsageError(`${logFile} already exists; refusing to overwrite.`);
        const { identity, mnemonic: words } = await Identity.create({ api: values.api });
        save(identity);
        emit({ ...summary(identity), log: logFile, mnemonic: words },
          `Created ${identity.did}\nLog written to ${logFile}\n\nMnemonic -- write it down, it is the ONLY way to recover this identity:\n${words}\n\nNo host yet: dito connect <username> gives it one.`);
        return 0;
      }
      case "show": {
        const log = parseVhLog(readLog());
        const did = log[0]!.state.id as string;
        const resolved = await resolveVhLog(did, log);
        emit({ did, method: "did:vh", versionId: resolved.meta.versionId, entries: log.length, deactivated: resolved.meta.deactivated, locations: locationsOf(did, log.at(-1)!.state).map(location => location.src), document: resolved.doc },
          `${did}\nentries: ${log.length}   version: ${resolved.meta.versionId}   deactivated: ${resolved.meta.deactivated}\n${JSON.stringify(resolved.doc, null, 2)}`);
        return 0;
      }
      case "fetch": {
        if (!isVhDid(rest[0])) throw new UsageError("Usage: dito fetch <did:vh:…> --watcher <origin> | --src <location>");
        if (existsSync(logFile)) throw new UsageError(`${logFile} already exists; refusing to overwrite.`);
        const text = await fetchLogFor(rest[0]);
        const resolved = await resolveRemembered(rest[0], parseVhLog(text));
        mkdirSync(dirname(logFile), { recursive: true });
        writeFileSync(logFile, text.endsWith("\n") ? text : `${text}\n`, { mode: 0o644 });
        emit({ did: rest[0], log: logFile, versionId: resolved.meta.versionId }, `Saved ${rest[0]} to ${logFile}`);
        return 0;
      }
      case "verify": {
        const arg = rest[0];
        if (isVhDid(arg)) {
          const resolved = await resolveRemembered(arg, parseVhLog(await fetchLogFor(arg)));
          emit({ ok: true, did: arg, versionId: resolved.meta.versionId }, `OK  ${arg}  (${resolved.meta.versionId})`);
          return 0;
        }
        const source = arg ?? logFile;
        const text = /^https?:\/\//.test(source) ? await (await fetch(source, { cache: "no-store" })).text() : readFileSync(source, "utf8");
        const log = parseVhLog(text);
        const did = log[0]!.state.id as string;
        const resolved = await resolveVhLog(did, log);
        emit({ ok: true, did, entries: log.length, versionId: resolved.meta.versionId }, `OK  ${did}  (${log.length} entries, ${resolved.meta.versionId})`);
        return 0;
      }
      case "forget": {
        if (!isVhDid(rest[0])) throw new UsageError("Usage: dito forget <did:vh:…>");
        const store = memory();
        if (!store) throw new UsageError("--no-memory leaves nothing to forget.");
        const forgotten = store.forget(`did:vh:${parseVhDid(rest[0]).scid}`);
        emit({ did: rest[0], forgotten }, forgotten ? `Forgot ${rest[0]}. The next verify or fetch accepts any valid log.` : `Nothing remembered for ${rest[0]}.`);
        return 0;
      }
      case "connect": {
        if (!rest[0]) throw new UsageError("Usage: dito connect <username> [--domain did.md]");
        const identity = await open();
        const result = await identity.connect({ username: rest[0], domain: values.domain });
        save(identity);
        emit({ ...summary(identity), logUrl: result.logUrl, ...(result.cleanupError ? { warning: result.cleanupError.message } : {}) },
          `Published ${identity.did}\n${result.logUrl}${result.cleanupError ? `\nwarning: previous location not cleaned up: ${result.cleanupError.message}` : ""}`);
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
        emit({ ...summary(identity), didWeb: moved.didWeb, previousSrc: moved.previousSrc, wrote: out },
          `${moved.did}\n${moved.didWeb}\nWrote did.jsonl and did.json to ${out}/\nServe them at ${moved.src}/.well-known/ (CORS: Access-Control-Allow-Origin: *), then: dito verify ${moved.did} --src ${moved.src}`);
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
        const log = parseVhLog(readLog());
        const did = log[0]!.state.id as string;
        const resolved = await resolveVhLog(did, log);
        const out = join(values.out ?? ".", ".well-known");
        mkdirSync(out, { recursive: true });
        writeFileSync(join(out, "did.jsonl"), serializeVhLog(log));
        // The did:web document of the first location is derived from the log, never written by hand.
        const here = locationsOf(did, log.at(-1)!.state)[0];
        if (here && resolved.doc) writeFileSync(join(out, "did.json"), buildDidJson(resolved.doc, here.didWeb));
        emit({ did, versionId: resolved.meta.versionId, wrote: out }, `Wrote did.jsonl${here ? " and did.json" : ""} for ${did} (${resolved.meta.versionId}) to ${out}/${here ? "" : "\n(no location yet, so no did.json: dito connect or dito domain first)"}`);
        return 0;
      }
      case "publish": {
        // Needs no secret: PUT of the full log to the location its own document names, which the host validates itself.
        const log = parseVhLog(readLog());
        const did = log[0]!.state.id as string;
        await resolveVhLog(did, log);
        const here = locationsOf(did, log.at(-1)!.state)[0];
        if (!here) throw new UsageError("This identity names no location yet: dito connect <username> first.");
        await client.publish(here.src, serializeVhLog(log));
        const live = await client.read(here.src);
        emit({ did, logUrl: `${client.baseUrl(here.src)}did.jsonl`, versionId: log.at(-1)!.versionId, verified: live === serializeVhLog(log) },
          `Published ${did}\n${client.baseUrl(here.src)}did.jsonl\nverified: ${live === serializeVhLog(log) ? log.at(-1)!.versionId : "NOT confirmed"}`);
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
        if (values.local) {
          // The log only; the host is not contacted (use with `export` or `publish` later).
          const draft = JSON.parse(JSON.stringify(identity.state));
          await identity.commit(await identity.prepareUpdate(edit ? edit(draft) : draft));
        } else await identity.publishUpdate(edit);
        save(identity);
        emit({ ...summary(identity) }, `Updated ${identity.did} (${identity.entries.length} entries)`);
        return 0;
      }
      case "unpublish": {
        const identity = await open();
        await identity.unpublish();
        emit({ ...summary(identity), unpublished: true }, `Removed ${identity.did} from its host. (This does not deactivate the DID.)`);
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
