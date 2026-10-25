/**
 * The did:vh half of the CLI: the same commands as for a did:webvh identity, for a log whose first entry says
 * `did:vh:1.0` (or `dito new --method vh`). `vhCommand` returns undefined for anything that is not its business, and
 * cli.ts carries on with the did:webvh commands.
 *
 * Differences a user meets: a did:vh DID has no host, so the log of someone else's DID is found with `--watcher <origin>`
 * (a host that serves `GET /log?scid=`) or `--src <location>`; `connect` is one update entry that makes the document name
 * the place; there is no `domain`/`github` (those are did:webvh moves).
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { openIdentityContainer } from "../../wallet/src/identity-container.ts";
import { seedFromMnemonic } from "../../wallet/src/did-webvh.ts";
import { VhIdentity } from "../../wallet/src/vh-identity.ts";
import { VhHostingClient, locationsOf, parseVhDid, parseVhLog, resolveVhLog, serializeVhLog, type VhLogEntry } from "../../vh/src/index.ts";
import type { FileVersionMemory } from "./version-memory.ts";

export class VhUsageError extends Error {}

export type VhContext = {
  values: { log?: string; api?: string; domain?: string; out?: string; local?: boolean; jwe?: boolean; method?: string; src?: string; watcher?: string; json?: boolean; "no-memory"?: boolean };
  rest: string[];
  emit(data: Record<string, unknown>, human: string): void;
  mnemonic(): Promise<string>;
  /** The version memory, or undefined with --no-memory. */
  memory(): FileVersionMemory | undefined;
  logFile: string;
};

/** Is this `did.jsonl` text a did:vh log? (Its first entry says so; nothing else is parsed.) */
export function isVhLogText(text: string): boolean {
  try {
    const first = JSON.parse(text.slice(0, text.indexOf("\n") === -1 ? undefined : text.indexOf("\n"))) as { parameters?: { method?: unknown } };
    return typeof first.parameters?.method === "string" && first.parameters.method.startsWith("did:vh:");
  } catch { return false; }
}

const isVhDid = (value: unknown): value is string => typeof value === "string" && value.startsWith("did:vh:");

/** Where the log of a did:vh DID is fetched from, as the user said. */
async function fetchLogFor(did: string, ctx: VhContext, client: VhHostingClient): Promise<string> {
  const { scid } = parseVhDid(did);
  let text: string | null;
  if (ctx.values.src) text = await client.read(ctx.values.src);
  else if (ctx.values.watcher) text = await client.readByScid(ctx.values.watcher, scid);
  else throw new VhUsageError(`A did:vh DID names no location: say where its log is, with --watcher <origin> (a host serving /log?scid=) or --src <location>.`);
  if (text === null) throw new Error("No DID log found there.");
  return text;
}

async function resolveRemembered(did: string, ctx: VhContext, log: VhLogEntry[]) {
  try { return await resolveVhLog(did, log, { memory: ctx.memory() }); }
  catch (error) {
    const name = (error as Error).name;
    if (name === "StaleLogError" || name === "ForkedLogError") {
      throw new Error(`${(error as Error).message} ${name === "StaleLogError" ? "This copy is older than one verified before." : "This log forks the one verified before."} If that is expected (a restored host, a recovered log), run \`dito forget ${did}\` or use --no-memory.`);
    }
    throw error;
  }
}

export async function vhCommand(command: string, ctx: VhContext): Promise<number | undefined> {
  const { values, rest, emit } = ctx;
  const save = (identity: VhIdentity) => { mkdirSync(dirname(ctx.logFile), { recursive: true }); writeFileSync(ctx.logFile, identity.logText(), { mode: 0o644 }); };
  const summary = (identity: VhIdentity) => ({ did: identity.did, method: "did:vh", provisional: identity.isProvisional, entries: identity.entries.length, locations: identity.locations.map(location => location.src) });
  const logText = () => {
    if (!existsSync(ctx.logFile)) throw new VhUsageError(`No DID log at ${ctx.logFile}. Run \`dito new\` first (or pass --log).`);
    return readFileSync(ctx.logFile, "utf8");
  };
  const mine = () => existsSync(ctx.logFile) && isVhLogText(readFileSync(ctx.logFile, "utf8"));
  const open = async () => VhIdentity.open({ mnemonic: await ctx.mnemonic(), log: logText() });
  const client = new VhHostingClient();

  switch (command) {
    case "new": {
      if (values.method !== "vh") return undefined;
      if (existsSync(ctx.logFile)) throw new VhUsageError(`${ctx.logFile} already exists; refusing to overwrite.`);
      const { identity, mnemonic: words } = await VhIdentity.create({ api: values.api });
      save(identity);
      emit({ ...summary(identity), log: ctx.logFile, mnemonic: words },
        `Created ${identity.did}\nLog written to ${ctx.logFile}\n\nMnemonic -- write it down, it is the ONLY way to recover this identity:\n${words}\n\nNo host yet: dito connect <username> gives it one.`);
      return 0;
    }
    case "show": {
      if (!mine()) return undefined;
      const text = logText();
      const log = parseVhLog(text);
      const did = log[0]!.state.id as string;
      const resolved = await resolveVhLog(did, log);
      emit({ did, method: "did:vh", versionId: resolved.meta.versionId, entries: log.length, deactivated: resolved.meta.deactivated, locations: locationsOf(did, log.at(-1)!.state).map(location => location.src), document: resolved.doc },
        `${did}\nentries: ${log.length}   version: ${resolved.meta.versionId}   deactivated: ${resolved.meta.deactivated}\n${JSON.stringify(resolved.doc, null, 2)}`);
      return 0;
    }
    case "verify": {
      const arg = rest[0];
      if (isVhDid(arg)) {
        const log = parseVhLog(await fetchLogFor(arg, ctx, client));
        const resolved = await resolveRemembered(arg, ctx, log);
        emit({ ok: true, did: arg, versionId: resolved.meta.versionId }, `OK  ${arg}  (${resolved.meta.versionId})`);
        return 0;
      }
      const source = arg ?? ctx.logFile;
      const text = /^https?:\/\//.test(source) ? await (await fetch(source, { cache: "no-store" })).text() : existsSync(source) ? readFileSync(source, "utf8") : undefined;
      if (text === undefined || !isVhLogText(text)) return undefined;
      const log = parseVhLog(text);
      const did = log[0]!.state.id as string;
      const resolved = await resolveVhLog(did, log);
      emit({ ok: true, did, entries: log.length, versionId: resolved.meta.versionId }, `OK  ${did}  (${log.length} entries, ${resolved.meta.versionId})`);
      return 0;
    }
    case "fetch": {
      if (!isVhDid(rest[0])) return undefined;
      if (existsSync(ctx.logFile)) throw new VhUsageError(`${ctx.logFile} already exists; refusing to overwrite.`);
      const text = await fetchLogFor(rest[0], ctx, client);
      const resolved = await resolveRemembered(rest[0], ctx, parseVhLog(text));
      mkdirSync(dirname(ctx.logFile), { recursive: true });
      writeFileSync(ctx.logFile, text.endsWith("\n") ? text : `${text}\n`, { mode: 0o644 });
      emit({ did: rest[0], log: ctx.logFile, versionId: resolved.meta.versionId }, `Saved ${rest[0]} to ${ctx.logFile}`);
      return 0;
    }
    case "forget": {
      if (!isVhDid(rest[0])) return undefined;
      const store = ctx.memory();
      if (!store) throw new VhUsageError("--no-memory leaves nothing to forget.");
      const forgotten = store.forget(`did:vh:${parseVhDid(rest[0]).scid}`);
      emit({ did: rest[0], forgotten }, forgotten ? `Forgot ${rest[0]}. The next verify or fetch accepts any valid log.` : `Nothing remembered for ${rest[0]}.`);
      return 0;
    }
    case "connect": {
      if (!mine()) return undefined;
      if (!rest[0]) throw new VhUsageError("Usage: dito connect <username> [--domain did.md]");
      const identity = await open();
      const result = await identity.connect({ username: rest[0], domain: values.domain });
      save(identity);
      emit({ ...summary(identity), logUrl: result.logUrl, ...(result.cleanupError ? { warning: result.cleanupError.message } : {}) },
        `Published ${identity.did}\n${result.logUrl}${result.cleanupError ? `\nwarning: previous location not cleaned up: ${result.cleanupError.message}` : ""}`);
      return 0;
    }
    case "publish": {
      if (!mine()) return undefined;
      // Needs no secret: PUT of the full log to the location its own document names, which the host validates itself.
      const log = parseVhLog(logText());
      const did = log[0]!.state.id as string;
      await resolveVhLog(did, log);
      const here = locationsOf(did, log.at(-1)!.state)[0];
      if (!here) throw new VhUsageError("This identity names no location yet: dito connect <username> first.");
      await client.publish(here.src, serializeVhLog(log));
      const live = await client.read(here.src);
      emit({ did, logUrl: `${client.baseUrl(here.src)}did.jsonl`, versionId: log.at(-1)!.versionId, verified: live === serializeVhLog(log) },
        `Published ${did}\n${client.baseUrl(here.src)}did.jsonl\nverified: ${live === serializeVhLog(log) ? log.at(-1)!.versionId : "NOT confirmed"}`);
      return 0;
    }
    case "rotate":
    case "service": {
      if (!mine()) return undefined;
      const identity = await open();
      let edit: ((state: Record<string, any>) => Record<string, any>) | undefined;
      if (command === "service") {
        const [action, id, type, endpoint] = rest;
        if (action === "add" && id && type && endpoint) edit = state => ({ ...state, service: [...(state.service ?? []).filter((s: any) => s.id !== id), { id, type, serviceEndpoint: endpoint }] });
        else if (action === "remove" && id) edit = state => ({ ...state, service: (state.service ?? []).filter((s: any) => s.id !== id) });
        else throw new VhUsageError("Usage: dito service add <id> <type> <endpoint> | dito service remove <id>");
      }
      if (values.local) {
        // The log only; the host is not contacted (use with `publish` later).
        const draft = JSON.parse(JSON.stringify(identity.state));
        await identity.commit(await identity.prepareUpdate(edit ? edit(draft) : draft));
      } else await identity.publishUpdate(edit);
      save(identity);
      emit({ ...summary(identity) }, `Updated ${identity.did} (${identity.entries.length} entries)`);
      return 0;
    }
    case "unpublish": {
      if (!mine()) return undefined;
      const identity = await open();
      await identity.unpublish();
      emit({ ...summary(identity), unpublished: true }, `Removed ${identity.did} from its host. (This does not deactivate the DID.)`);
      return 0;
    }
    case "export": {
      if (!mine()) return undefined;
      if (values.jwe) {
        const { scid, jwe } = await (await open()).exportContainer();
        mkdirSync(values.out ?? ".", { recursive: true });
        const file = join(values.out ?? ".", `${scid}.jwe`);
        writeFileSync(file, jwe, { mode: 0o600 });
        emit({ scid, wrote: file }, `Wrote ${file} (open it with the same mnemonic: dito import ${file})`);
        return 0;
      }
      // The log to serve; did.json is the host's to derive, and is not written here.
      const log = parseVhLog(logText());
      await resolveVhLog(log[0]!.state.id as string, log);
      const out = join(values.out ?? ".", ".well-known");
      mkdirSync(out, { recursive: true });
      writeFileSync(join(out, "did.jsonl"), serializeVhLog(log));
      emit({ did: log[0]!.state.id, versionId: log.at(-1)!.versionId, wrote: out }, `Wrote did.jsonl for ${log[0]!.state.id} to ${out}/ (a host derives did.json from it; see SPEC-webvh-hosting.md section 11)`);
      return 0;
    }
    case "import": {
      if (!rest[0] || !existsSync(rest[0])) return undefined;
      const jwe = readFileSync(rest[0], "utf8").trim();
      const container = await openIdentityContainer(jwe, seedFromMnemonic(await ctx.mnemonic(), "Passphrase")).catch(() => undefined);
      if (!container || !isVhLogText(container.didJsonl)) return undefined;
      if (existsSync(ctx.logFile)) throw new VhUsageError(`${ctx.logFile} already exists; refusing to overwrite.`);
      const identity = await VhIdentity.fromContainer({ jwe, mnemonic: await ctx.mnemonic() });
      save(identity);
      emit({ ...summary(identity), log: ctx.logFile }, `Restored ${identity.did}\nLog written to ${ctx.logFile}`);
      return 0;
    }
    default:
      return undefined;
  }
}
