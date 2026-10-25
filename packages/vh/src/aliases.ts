/**
 * The two ways a did:vh document names the place its log is published
 * (REPORT-didvh.md §2.10, PLAN-didvh.md §1.1):
 *
 *   did:web:alice.did.md                              the did:web DID of the location (also: the location rule, policy.ts)
 *   did:vh:<SCID>?src=https://alice.did.md            a did:vh DID URL whose `src` is the web location (didvh-spec: Advertising DID Log Sources)
 */
import { didWebFor } from "./didweb.ts";
import { parseWebLocation, type SrcOptions } from "./src.ts";

/** A `src` as a DID URL query value: only what would end the value early is escaped. */
export function encodeSrc(src: string): string { return src.replace(/[%&=#+\s]/g, character => `%${character.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0")}`); }

/** `did:vh:<scid>?src=<location>` for a web location (no trailing slash). */
export function srcAlias(did: string, src: string): string { return `${did}?src=${encodeSrc(src.replace(/\/+$/, ""))}`; }

export type Location = { src: string; didWeb: string; alias: string };

/** The web location a `did:vh:<scid>?src=…` alias names, or undefined for any other string. */
export function locationOfAlias(did: string, alias: unknown, options: SrcOptions = {}): string | undefined {
  if (typeof alias !== "string" || !alias.startsWith(`${did}?src=`)) return undefined;
  let value: string;
  try { value = decodeURIComponent(alias.slice(`${did}?src=`.length)); } catch { return undefined; }
  try { parseWebLocation(value, options); } catch { return undefined; }
  return value.replace(/\/+$/, "");
}

/** The locations a document says its log is published at, in the order it lists them. */
export function locationsOf(did: string, document: Record<string, any>, options: SrcOptions = {}): Location[] {
  const aliases: unknown[] = Array.isArray(document.alsoKnownAs) ? document.alsoKnownAs : [];
  const found: Location[] = [];
  for (const alias of aliases) {
    const src = locationOfAlias(did, alias, options);
    if (src !== undefined && !found.some(location => location.src === src)) found.push({ src, didWeb: didWebFor(src, options), alias: alias as string });
  }
  return found;
}

/** `alsoKnownAs` for a document published at `src`: its did:web DID and its `?src=` alias, ahead of whatever else it names. */
export function withLocation(document: Record<string, any>, did: string, add: string | undefined, remove?: string, options: SrcOptions = {}): Record<string, any> {
  const dropped = remove === undefined ? undefined : { didWeb: didWebFor(remove, options), alias: srcAlias(did, remove) };
  const kept = (Array.isArray(document.alsoKnownAs) ? document.alsoKnownAs as unknown[] : [])
    .filter(alias => typeof alias === "string" && alias !== dropped?.didWeb && locationOfAlias(did, alias, options) !== remove?.replace(/\/+$/, "")) as string[];
  const added = add === undefined ? [] : [didWebFor(add, options), srcAlias(did, add)];
  return { ...document, alsoKnownAs: [...new Set([...added, ...kept])] };
}
