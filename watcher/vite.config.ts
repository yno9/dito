import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vite'
import { voidPlugin } from 'void'

const target = process.env.WATCHER_TARGET === 'cloudflare' ? 'cloudflare' : 'node'

export default defineConfig({
  plugins: [voidPlugin()],
  // `#store` is the one thing that differs between the targets: Node cannot use D1, Workers cannot use node:sqlite.
  resolve: { alias: { '#store': fileURLToPath(new URL(`./lib/store.${target}.ts`, import.meta.url)) } },
})
