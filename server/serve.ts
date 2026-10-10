/**
 * Minimal fetch-style HTTP server on node:http: takes a (Request) => Response
 * handler, so the route modules stay runtime-neutral Web-standard code.
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { Readable } from "node:stream";

export interface ServeOptions {
  port: number;
  hostname?: string;
  fetch: (request: Request) => Response | Promise<Response>;
}

export interface Served {
  hostname: string;
  port: number;
  stop(closeActiveConnections?: boolean): void;
}

function toRequest(incoming: IncomingMessage): Request {
  const headers = new Headers();
  for (const [name, value] of Object.entries(incoming.headers)) {
    if (Array.isArray(value)) for (const item of value) headers.append(name, item);
    else if (value !== undefined) headers.set(name, value);
  }
  const url = `http://${incoming.headers.host ?? "localhost"}${incoming.url ?? "/"}`;
  const method = incoming.method ?? "GET";
  const body = method === "GET" || method === "HEAD" ? undefined : (Readable.toWeb(incoming) as ReadableStream);
  return new Request(url, { method, headers, body, duplex: "half" } as RequestInit);
}

async function send(response: Response, outgoing: ServerResponse): Promise<void> {
  const headers: Record<string, string | string[]> = {};
  for (const [name, value] of response.headers) headers[name] = value;
  const cookies = response.headers.getSetCookie();
  if (cookies.length) headers["set-cookie"] = cookies;
  outgoing.writeHead(response.status, headers);
  if (!response.body) return void outgoing.end();
  Readable.fromWeb(response.body as never).pipe(outgoing);
}

export function serve(options: ServeOptions): Served {
  const server = createServer(async (incoming, outgoing) => {
    try {
      await send(await options.fetch(toRequest(incoming)), outgoing);
    } catch (error) {
      console.error(error);
      if (!outgoing.headersSent) outgoing.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
      outgoing.end("internal error\n");
    }
  });
  const hostname = options.hostname ?? "0.0.0.0";
  server.listen(options.port, hostname);
  return {
    hostname,
    get port() { return (server.address() as AddressInfo | null)?.port ?? options.port; },
    stop(closeActiveConnections) {
      server.close();
      if (closeActiveConnections) server.closeAllConnections();
    },
  };
}
