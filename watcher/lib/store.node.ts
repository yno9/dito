import type { WatcherStore } from '../../packages/watcher/src/store.ts'
import { SqliteWatcherStore } from '../../packages/watcher/src/sqlite-store.ts'

/** Node: a SQLite file, `WATCHER_DB` (default `./watcher.sqlite`). */
export function openStore(env: Record<string, unknown>): WatcherStore {
  return new SqliteWatcherStore(String(env.WATCHER_DB ?? './watcher.sqlite'))
}
