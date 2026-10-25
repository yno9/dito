import { defineHandler } from 'void'
import { watcherFor } from '../../lib/instance.ts'

// VH-Log: Watcher HTTP API Operations. The logic is packages/watcher; a route only hands the request over.
const serve = defineHandler(async c => watcherFor(c).handle(c.req.raw))
export const GET = serve
export const POST = serve
export const OPTIONS = serve
