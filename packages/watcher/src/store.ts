/** What a watcher keeps of one did:vh: the whole log it last accepted, and every fork of it that was seen since. */
export type Fork = {
  /** The version at which the other continuation differs. */
  versionNumber: number;
  /** The versionId the other continuation has there (the one held has `versionIds[versionNumber - 1]`). */
  versionId: string;
  seenAt: string;
  /** Where the other continuation was fetched from. */
  source: string;
};

export type WatchedLog = {
  scid: string;
  did: string;
  /** The log as JSON Lines, exactly as verified. */
  text: string;
  /** The versionId of every entry, in order (position `i` is version `i + 1`). */
  versionIds: string[];
  /** The web location the log was last fetched from: where a notification without a `src` is followed up. */
  source?: string;
  forks: Fork[];
  updatedAt: string;
};

/** Where a watcher keeps its logs. Small on purpose: every host (Node: SQLite, Cloudflare: D1) writes one adapter. */
export interface WatcherStore {
  get(scid: string): Promise<WatchedLog | null>;
  put(log: WatchedLog): Promise<void>;
  delete(scid: string): Promise<boolean>;
}

export class MemoryWatcherStore implements WatcherStore {
  private readonly logs = new Map<string, WatchedLog>();
  async get(scid: string) { const found = this.logs.get(scid); return found ? structuredClone(found) : null; }
  async put(log: WatchedLog) { this.logs.set(log.scid, structuredClone(log)); }
  async delete(scid: string) { return this.logs.delete(scid); }
}
