/**
 * fetch() that honors a caller-set `Host` header. Node's built-in fetch always
 * replaces Host with the URL's host, but did.md routes every identity by Host
 * (`alice.did.md`), so local tests, the conformance CLI and the test-only
 * IDENTITY_FETCH_BASE_URL escape hatch need to address 127.0.0.1 as that host.
 * Anything without an explicit Host goes straight to the built-in fetch.
 */
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";

const builtinFetch = globalThis.fetch;

export const fetchWithHost: typeof fetch = async (input, init) => {
  const probe = new Request(input, init);
  if (!probe.headers.has("host")) return builtinFetch(input, init);
  const url = new URL(probe.url);
  const body = probe.method === "GET" || probe.method === "HEAD" ? undefined : Buffer.from(await probe.arrayBuffer());
  const send = url.protocol === "https:" ? httpsRequest : httpRequest;
  return new Promise<Response>((resolve, reject) => {
    const outgoing = send(url, { method: probe.method, headers: { ...Object.fromEntries(probe.headers), ...(body ? { "content-length": String(body.length) } : {}) } }, incoming => {
      const chunks: Buffer[] = [];
      incoming.on("data", chunk => chunks.push(chunk));
      incoming.on("end", () => {
        const headers = new Headers();
        for (const [name, value] of Object.entries(incoming.headers)) for (const item of [value].flat()) if (item !== undefined) headers.append(name, item);
        const status = incoming.statusCode ?? 502;
        const empty = status === 204 || status === 304 || probe.method === "HEAD";
        resolve(new Response(empty ? null : Buffer.concat(chunks), { status, headers }));
      });
      incoming.on("error", reject);
    });
    outgoing.on("error", reject);
    outgoing.end(body);
  });
};
