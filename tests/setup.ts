// didwebvh-ts reads NODE_ENV once, at import, and when it is "test" (which
// vitest sets) createDID/updateDID write every log they build to
// ./test/logs/*.jsonl. Keep tests from littering the repo; see JOURNAL.md.
process.env.NODE_ENV = "development";

// Node's fetch ignores a caller-set Host header; the host routes by it.
import { fetchWithHost } from "../server/host-fetch.ts";
globalThis.fetch = fetchWithHost;
