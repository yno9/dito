import type { WatchedLog, WatcherStore } from "./store.ts";

/** The part of Cloudflare's D1 binding used here (so this file needs no Cloudflare types). */
export interface D1Like {
  prepare(sql: string): { bind(...values: unknown[]): { first<T = Record<string, unknown>>(): Promise<T | null>; run(): Promise<{ meta?: { changes?: number } }> } };
  exec(sql: string): Promise<unknown>;
}

const SCHEMA = "CREATE TABLE IF NOT EXISTS watched_logs (scid TEXT PRIMARY KEY, did TEXT NOT NULL, text TEXT NOT NULL, version_ids TEXT NOT NULL, source TEXT, forks TEXT NOT NULL, updated_at TEXT NOT NULL)";

/** A watcher's logs in Cloudflare D1: one row per SCID. */
export class D1WatcherStore implements WatcherStore {
  private ready: Promise<unknown> | undefined;
  constructor(private readonly db: D1Like) {}

  private schema() { return this.ready ??= this.db.exec(SCHEMA); }

  async get(scid: string): Promise<WatchedLog | null> {
    await this.schema();
    const row = await this.db.prepare("SELECT * FROM watched_logs WHERE scid = ?").bind(scid).first<Record<string, string | null>>();
    if (!row) return null;
    return {
      scid: row.scid!, did: row.did!, text: row.text!, versionIds: JSON.parse(row.version_ids!), forks: JSON.parse(row.forks!),
      updatedAt: row.updated_at!, ...(row.source ? { source: row.source } : {}),
    };
  }

  async put(log: WatchedLog): Promise<void> {
    await this.schema();
    await this.db.prepare("INSERT OR REPLACE INTO watched_logs (scid, did, text, version_ids, source, forks, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .bind(log.scid, log.did, log.text, JSON.stringify(log.versionIds), log.source ?? null, JSON.stringify(log.forks), log.updatedAt).run();
  }

  async delete(scid: string): Promise<boolean> {
    await this.schema();
    const result = await this.db.prepare("DELETE FROM watched_logs WHERE scid = ?").bind(scid).run();
    return (result.meta?.changes ?? 0) > 0;
  }
}
