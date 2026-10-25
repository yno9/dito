// Node's fetch ignores a caller-set Host header; the host routes by it.
import { fetchWithHost } from "../server/host-fetch.ts";
globalThis.fetch = fetchWithHost;
