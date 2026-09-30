// didwebvh-ts reads NODE_ENV once, at import, and when it is "test" (which
// `bun test` sets) createDID/updateDID write every log they build to
// ./test/logs/*.jsonl. Keep tests from littering the repo; see JOURNAL.md.
process.env.NODE_ENV = "development";
