import type { WatcherStore } from '../../packages/watcher/src/store.ts'
import { D1WatcherStore, type D1Like } from '../../packages/watcher/src/d1-store.ts'

/** Cloudflare: the D1 database bound as `DB`. */
export function openStore(env: Record<string, unknown>): WatcherStore {
  if (!env.DB) throw new Error('The D1 binding DB is missing (void.config.ts: cloudflare.d1_databases).')
  return new D1WatcherStore(env.DB as D1Like)
}
