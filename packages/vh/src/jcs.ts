/**
 * JSON Canonicalization Scheme (RFC 8785) for what a VH-Log entry contains:
 * objects, arrays, strings, finite numbers, booleans and null. Keys sort in
 * UTF-16 code-unit order (plain JS string comparison); strings and numbers
 * serialise as JSON.stringify does, which is ECMAScript's Number-to-String and
 * QuoteJSONString, the forms RFC 8785 requires.
 */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("A non-finite number cannot be canonicalised.");
    return Object.is(value, -0) ? "0" : JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const parts = Object.keys(record).filter(key => record[key] !== undefined).sort().map(key => `${JSON.stringify(key)}:${canonicalize(record[key])}`);
    return `{${parts.join(",")}}`;
  }
  throw new Error(`A ${typeof value} cannot be canonicalised.`);
}
