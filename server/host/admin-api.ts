/**
 * What v2 admin asks of this host: its numbers, and two operations. It listens on this host's own port (127.0.0.1:8787), which Caddy
 * never routes /admin/* to, and it answers only a caller with the bearer token v2 admin shares with it; with no token file there is
 * no admin interface at all.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { timingSafeEqual } from "node:crypto";
import { join } from "node:path";
import { DATA_DIR, hostStats, safeName, setIdentityStopped } from "./identity-host.ts";

const env: Record<string, string | undefined> = (globalThis as { process?: { env: Record<string, string | undefined> } }).process?.env ?? {};
const TOKEN_FILE = env.V2_ADMIN_TOKEN_FILE ?? "/etc/v2-admin/tokens/dito";

function token(): string | null { try { return readFileSync(TOKEN_FILE, "utf8").trim() || null; } catch { return null; } }
function allowed(request: Request): boolean {
  const expected = token(); if (!expected) return false;
  const given = /^Bearer (.+)$/.exec(request.headers.get("authorization") ?? "")?.[1] ?? "";
  const a = Buffer.from(given), b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}
const reply = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });

let diskCache: { bytes: number; at: number } | undefined;
function diskBytes(): number {
  if (diskCache && Date.now() - diskCache.at < 60_000) return diskCache.bytes;
  let bytes = 0;
  try { for (const name of readdirSync(join(DATA_DIR, "logs"))) for (const file of readdirSync(join(DATA_DIR, "logs", name))) { try { bytes += statSync(join(DATA_DIR, "logs", name, file)).size; } catch { /* gone meanwhile */ } } } catch { /* no data yet */ }
  diskCache = { bytes, at: Date.now() };
  return bytes;
}

export async function adminFetch(request: Request, url: URL): Promise<Response | undefined> {
  if (!url.pathname.startsWith("/admin/")) return undefined;
  if (!allowed(request)) return new Response("not found\n", { status: 404 });
  if (url.pathname === "/admin/metrics" && request.method === "GET") {
    const stats = await hostStats();
    return reply(200, { metrics: {
      identities: { label: "Identities", value: stats.identities, unit: "", kind: "gauge" },
      createdThisHour: { label: "New in the last hour", value: stats.createdThisHour, kind: "gauge" },
      created: { label: "Created since start", value: stats.created, kind: "counter" },
      refusedRate: { label: "Refused: too many new", value: stats.refusedRate, kind: "counter" },
      refusedCapacity: { label: "Refused: host full", value: stats.refusedCapacity, kind: "counter" },
      refusedBusy: { label: "Refused: busy", value: stats.refusedBusy, kind: "counter" },
      refusedReserved: { label: "Refused: reserved name", value: stats.refusedReserved, kind: "counter" },
      refusedStopped: { label: "Writes to stopped identities", value: stats.refusedStopped, kind: "counter" },
      validating: { label: "Logs being checked now", value: stats.validating, kind: "gauge" },
      diskKiB: { label: "Identity data", value: Math.round(diskBytes() / 1024), unit: "KiB", kind: "gauge" },
    } });
  }
  const action = /^\/admin\/actions\/(stop-identity|release-identity)$/.exec(url.pathname)?.[1];
  if (action && request.method === "POST") {
    const params = ((await request.json().catch(() => ({}))) as { params?: { username?: unknown; reason?: unknown } }).params ?? {};
    let username: string;
    try { username = safeName(String(params.username ?? ""), "username"); } catch (error) { return reply(400, { error: (error as Error).message }); }
    const result = await setIdentityStopped(username, action === "stop-identity" ? String(params.reason ?? "stopped by the operator").slice(0, 200) : null);
    const message = { stopped: `${username} is stopped: its documents are no longer served and it cannot be written (a copy at the CDN may last 30 seconds)`, released: `${username} is let back`, unchanged: `${username} was already ${action === "stop-identity" ? "stopped" : "free"}`, unknown: `${username} has no identity here` }[result];
    return reply(result === "unknown" ? 404 : 200, { message });
  }
  return new Response("not found\n", { status: 404 });
}
