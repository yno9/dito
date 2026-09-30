/**
 * @metamask/browser-passworder is browserifiable, but its published ESM
 * bundle still refers to the Node global `Buffer` at call time.  Supply only
 * the tiny, standards-based subset it uses so the local password vault works
 * in Safari, Firefox, and Chromium without a Node polyfill bundle.
 */
class BrowserBuffer extends Uint8Array {
  static from(value: string | ArrayLike<number>, encoding = "utf-8"): BrowserBuffer {
    if (typeof value !== "string") return new BrowserBuffer(value);
    if (encoding === "base64") {
      const binary = atob(value.replace(/\s/g, ""));
      return new BrowserBuffer(Uint8Array.from(binary, character => character.charCodeAt(0)));
    }
    if (encoding === "utf-8" || encoding === "utf8") return new BrowserBuffer(new TextEncoder().encode(value));
    throw new Error(`Unsupported browser Buffer encoding: ${encoding}`);
  }

  toString(encoding = "utf-8"): string {
    if (encoding === "base64") {
      let binary = "";
      for (const byte of this) binary += String.fromCharCode(byte);
      return btoa(binary);
    }
    if (encoding === "utf-8" || encoding === "utf8") return new TextDecoder().decode(this);
    return super.toString();
  }
}

if (typeof (globalThis as any).Buffer === "undefined") (globalThis as any).Buffer = BrowserBuffer;
