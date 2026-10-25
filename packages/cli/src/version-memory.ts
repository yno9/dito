/**
 * The CLI's memory of the newest version it has verified of each DID it was
 * asked about, in one small JSON file under the XDG state directory
 * (`$XDG_STATE_HOME/dito/versions.json`, default `~/.local/state/dito/versions.json`).
 *
 * It makes `dito verify <did>` and `dito fetch <did>` refuse a log that is older
 * than, or forks, one seen before (see packages/webvh/src/freshness.ts). The cost
 * is that a rollback which is *meant* (a host restored from a backup, a log
 * recovered from an old copy) is refused too, until the DID is forgotten:
 * `dito forget <did>`, or `--no-memory` for a single check.
 *
 * A file that cannot be read or parsed is an error, never an empty memory:
 * quietly starting over would switch the protection off exactly when something
 * had damaged it.
 */
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { KnownVersion, VersionMemory } from "../../webvh/src/freshness.ts";

export function versionMemoryPath(env: Record<string, string | undefined>): string {
  const state = env.XDG_STATE_HOME || join(env.HOME || homedir(), ".local", "state");
  return join(state, "dito", "versions.json");
}

export class FileVersionMemory implements VersionMemory {
  readonly path: string;
  constructor(path: string) { this.path = path; }

  private load(): Record<string, KnownVersion> {
    if (!existsSync(this.path)) return {};
    let parsed: unknown;
    try { parsed = JSON.parse(readFileSync(this.path, "utf8")); }
    catch { throw new Error(`${this.path} is not valid JSON. Fix or remove it, or pass --no-memory.`); }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error(`${this.path} is not a version memory. Fix or remove it, or pass --no-memory.`);
    for (const [key, value] of Object.entries(parsed)) {
      const v = value as Partial<KnownVersion> | null;
      if (!v || !Number.isInteger(v.versionNumber) || typeof v.versionId !== "string") throw new Error(`${this.path} has an invalid entry for ${key}. Fix or remove it, or pass --no-memory.`);
    }
    return parsed as Record<string, KnownVersion>;
  }

  private save(all: Record<string, KnownVersion>): void {
    mkdirSync(dirname(this.path), { recursive: true });
    const temporary = `${this.path}.${process.pid}.tmp`;
    writeFileSync(temporary, `${JSON.stringify(all, null, 1)}\n`);
    renameSync(temporary, this.path);
  }

  get(key: string): KnownVersion | undefined { return this.load()[key]; }
  set(key: string, version: KnownVersion): void { this.save({ ...this.load(), [key]: version }); }

  /** Forget a DID. True if there was anything to forget. */
  forget(key: string): boolean {
    const all = this.load();
    if (!(key in all)) return false;
    delete all[key];
    this.save(all);
    return true;
  }
}
