/**
 * The small shapes the host's request handling shares: JSON values, a request that is the client's fault
 * (`Invalid`, a 400), and strict object checks. No Node or Cloudflare dependency.
 */
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export type Obj = Record<string, Json>;
export class Invalid extends Error {}

export function isObj(value: unknown): value is Obj { return typeof value === "object" && value !== null && !Array.isArray(value); }
export function asObj(value: unknown, label: string): Obj { if (!isObj(value)) throw new Invalid(`${label} must be an object`); return value; }
export function own<T extends object>(v: T, key: string) { return Object.prototype.hasOwnProperty.call(v, key); }
export function onlyKeys(value: Obj, allowed: string[], label: string) { for (const key of Object.keys(value)) if (!allowed.includes(key)) throw new Invalid(`${label}.${key} is not an accepted member`); }
