/**
 * What this host will take, and from whom -- the numbers v2 admin can change while it runs (admin.manifest.json lists them;
 * v2-admin-settings.ts reads them from the snapshot the admin writes). Without an admin the defaults below are in force, and they
 * are the safe side: a host that anyone can write to must not let anyone fill its disk or its processor.
 */
import type { SettingDef } from "./v2-admin-settings.ts";

export interface HostLimits {
  /** The largest did.jsonl a host takes (a normal identity's log is a few KB; each rotation adds a few hundred bytes). */
  maxLogBytes: number
  /** routing.json and the other small JSON bodies. */
  maxJsonBytes: number
  /** How many identities this host keeps; a new one over it is refused. */
  maxIdentities: number
  /** Logs being verified at once (the work is the processor's; more than this get 503). */
  maxConcurrentValidations: number
  /** New identities in any hour, from everyone together. */
  createPerHour: number
  /** Names (beside the built-in list) that cannot be registered. */
  reservedNames: string[]
}

export const DEFAULT_LIMITS: HostLimits = {
  maxLogBytes: 256 << 10,
  maxJsonBytes: 64 << 10,
  maxIdentities: 20_000,
  maxConcurrentValidations: 4,
  createPerHour: 60,
  reservedNames: [],
}

/** The settings v2 admin holds for this host, with the range each may take (admin.manifest.json describes the same ones to the admin;
 * a test keeps the two together). */
export const LIMIT_SETTINGS: Record<string, SettingDef> = {
  "limits.maxLogBytes": { type: "integer", default: DEFAULT_LIMITS.maxLogBytes, min: 4096, max: 16777216 },
  "limits.maxJsonBytes": { type: "integer", default: DEFAULT_LIMITS.maxJsonBytes, min: 1024, max: 1048576 },
  "limits.maxIdentities": { type: "integer", default: DEFAULT_LIMITS.maxIdentities, min: 1, max: 1000000 },
  "limits.maxConcurrentValidations": { type: "integer", default: DEFAULT_LIMITS.maxConcurrentValidations, min: 1, max: 64 },
  "limits.createPerHour": { type: "integer", default: DEFAULT_LIMITS.createPerHour, min: 0, max: 100000 },
  "names.reserved": { type: "list", item: "string", default: DEFAULT_LIMITS.reservedNames, maxItems: 1000, maxLength: 63, pattern: "[a-z0-9-]+" },
};

let provider: () => HostLimits = () => DEFAULT_LIMITS
/** The entry point that reads v2 admin's snapshot installs it here; anything else keeps the defaults. */
export function setHostLimits(next: () => HostLimits): void { provider = next }
export function hostLimits(): HostLimits { return provider() }

/** The host refuses for a reason that is not the request's fault: 429 (too many new identities), 503 (busy), 403 (stopped). */
export class Refusal extends Error {
  // (Written out, not as parameter properties: this file is run as TypeScript with its types stripped, which cannot do those.)
  readonly status: 403 | 429 | 503
  readonly retryAfterSeconds: number | undefined
  constructor(status: 403 | 429 | 503, message: string, retryAfterSeconds?: number) { super(message); this.status = status; this.retryAfterSeconds = retryAfterSeconds }
}

/** A count of things in a sliding hour. */
export class HourlyCount {
  private times: number[] = []
  private readonly now: () => number
  constructor(now: () => number = Date.now) { this.now = now }
  count(): number { const since = this.now() - 3_600_000; this.times = this.times.filter(time => time > since); return this.times.length }
  add(): void { this.times.push(this.now()) }
}

/** At most `max` at once; the rest are turned away at once, not queued (a queue is what an attack fills). */
export class Gate {
  active = 0
  async run<T>(max: number, task: () => Promise<T>): Promise<T> {
    if (this.active >= max) throw new Refusal(503, 'the host is busy; try again shortly', 5)
    this.active += 1
    try { return await task() } finally { this.active -= 1 }
  }
}

/** The counters v2 admin shows. They start at zero when the process starts. */
export const counters = { created: 0, refusedBusy: 0, refusedRate: 0, refusedCapacity: 0, refusedReserved: 0, refusedStopped: 0 }
