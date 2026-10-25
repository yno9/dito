import { DatabaseSync } from "node:sqlite";
import type { WatchedLog, WatcherStore } from "./store.ts";

/** A watcher's logs in a SQLite file (Node, Bun with `node:sqlite`): one row per SCID. */
export class SqliteWatcherStore implements WatcherStore {
  private readonly db: DatabaseSync;

  constructor(path: string) {
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA journal_mode = WAL");
    this.db.exec("CREATE TABLE IF NOT EXISTS watched_logs (scid TEXT PRIMARY KEY, did TEXT NOT NULL, text TEXT NOT NULL, version_ids TEXT NOT NULL, source TEXT, forks TEXT NOT NULL, updated_at TEXT NOT NULL)");
  }

  async get(scid: string): Promise<WatchedLog | null> {
    const row = this.db.prepare("SELECT * FROM watched_logs WHERE scid = ?").get(scid) as Record<string, string | null> | undefined;
    if (!row) return null;
    return {
      scid: row.scid!, did: row.did!, text: row.text!, versionIds: JSON.parse(row.version_ids!), forks: JSON.parse(row.forks!),
      updatedAt: row.updated_at!, ...(row.source ? { source: row.source } : {}),
    };
  }

  async put(log: WatchedLog): Promise<void> {
    this.db.prepare("INSERT OR REPLACE INTO watched_logs (scid, did, text, version_ids, source, forks, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(log.scid, log.did, log.text, JSON.stringify(log.versionIds), log.source ?? null, JSON.stringify(log.forks), log.updatedAt);
  }

  async delete(scid: string): Promise<boolean> {
    return Number(this.db.prepare("DELETE FROM watched_logs WHERE scid = ?").run(scid).changes) > 0;
  }

  close() { this.db.close(); }
}
