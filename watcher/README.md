# did:vh watcher

A watcher for did:vh (didvh-spec: Watchers; VH-Log: Watcher HTTP API Operations). The logic is `packages/watcher`; this directory is a
[Void](https://void.cloud) app that runs it as a Node.js server or as a Cloudflare Worker.

It holds the newest log of each identity it is set up to watch, verified in full (SCID, hash chain, signatures), and records
when an identity shows two continuations of one history (a fork). It does not believe a log because of who sent it.

| | |
|---|---|
| `GET /log?scid=<SCID>` | the log held (`text/jsonl`), or 404. `x-did-vh-forks: <n>` when forks were seen. |
| `POST /log?id=did:vh:<SCID>?src=<location>` | "there is a newer log": the watcher fetches it from `src` (else from where it last fetched), verifies it and compares with the one held: `stored`, `updated`, `unchanged`, `stale` (200), `forked` (409). |
| `POST /log/delete?scid=<SCID>` | the operator's `WATCHER_ADMIN_TOKEN` as a bearer token only. |
| `GET /witness`, `/resource` | 501: witnesses are not supported (dito and biset refuse witnessed logs). |
| `GET /healthz` | |

**Who is watched** is the operator's list, because a notification makes this server fetch a URL: `WATCHER_ALLOW_HOSTS`
(comma separated; `alice.did.md`, or `*.did.md` for every name under it) and `WATCHER_ALLOW_SCIDS`. Both empty: nothing is watched.

## Node.js

```sh
pnpm install
pnpm build:node
WATCHER_ALLOW_HOSTS='*.did.md' WATCHER_DB=./watcher.sqlite WATCHER_ADMIN_TOKEN=… PORT=8788 node dist/ssr/index.js
```

Logs are kept in a SQLite file (`node:sqlite`, Node 24+).

## Cloudflare

```sh
wrangler d1 create did-vh-watcher        # put its id in void.config.ts (cloudflare.d1_databases)
pnpm build:cloudflare
```

Logs are kept in D1 (binding `DB`); `WATCHER_ALLOW_HOSTS`, `WATCHER_ALLOW_SCIDS` are Worker variables (`worker.vars`) and
`WATCHER_ADMIN_TOKEN` a secret. The Worker build is checked to build; it has not been run on Workers yet.

Void's own `void/db`, `void/kv` and `void/storage` are Cloudflare-only (they fail to compile on the Node target), so the store is
a small interface (`packages/watcher/src/store.ts`) with one adapter per target, chosen at build time by `WATCHER_TARGET`.
