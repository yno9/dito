import { defineConfig } from 'void/config'

// One app, two ways to run it: a Node server (`WATCHER_TARGET=node`, the default) or a Cloudflare Worker (`cloudflare`).
// Only the store differs (lib/store.node.ts or lib/store.cloudflare.ts, chosen in vite.config.ts); the watcher is packages/watcher.
const target = process.env.WATCHER_TARGET === 'cloudflare' ? 'cloudflare' : 'node'

export default defineConfig(target === 'node' ? { target } : {
  target,
  // The D1 database that holds the logs, and the operator's list of who may be watched (also settable as Worker variables).
  cloudflare: { d1_databases: [{ binding: 'DB', database_name: 'did-vh-watcher', database_id: 'create-with-wrangler-d1-create' }] },
  worker: { vars: { WATCHER_ALLOW_HOSTS: '', WATCHER_ALLOW_SCIDS: '' } },
})
