import { createWatcher } from '../../packages/watcher/src/watcher.ts'
import { openStore } from '#store'

const list = (value: unknown) => String(value ?? '').split(',').map(item => item.trim()).filter(Boolean)

/** The environment a request runs in: Worker bindings and variables on Cloudflare, process.env on Node. */
function environment(c: { env?: unknown }): Record<string, unknown> {
  return { ...(typeof process !== 'undefined' ? process.env : {}), ...((c.env ?? {}) as Record<string, unknown>) }
}

let made: ReturnType<typeof createWatcher> | undefined

/** One watcher per server (or per Worker isolate): its store and who it is set up to watch come from the environment. */
export function watcherFor(c: { env?: unknown }) {
  if (made) return made
  const env = environment(c)
  made = createWatcher({
    store: openStore(env),
    allow: { hosts: list(env.WATCHER_ALLOW_HOSTS), scids: list(env.WATCHER_ALLOW_SCIDS) },
    ...(env.WATCHER_ADMIN_TOKEN ? { adminToken: String(env.WATCHER_ADMIN_TOKEN) } : {}),
  })
  return made
}
