import { defineHandler } from 'void'
import { watcherFor } from '../lib/instance.ts'

const serve = defineHandler(async c => watcherFor(c).handle(c.req.raw))
export const GET = serve
export const POST = serve
export const OPTIONS = serve
