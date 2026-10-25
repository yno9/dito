# dito

**A generic `did:vh` wallet, an open hosting protocol for `did:vh` logs, and a host.**

Every identity is yours to dispose of: to use, or to walk away from. You keep the keys; hosts only
publish a signed log, and any host can be swapped for another without asking anyone.

| | what it is |
|---|---|
| **dito** (`client/`, `public/`) | The wallet: one self-contained `index.html` you can also open from disk. One 24-word passphrase, deterministic keys, permanent pre-rotation. Private keys never leave the browser. |
| **vh-hosting/1** ([SPEC-vh-hosting.md](SPEC-vh-hosting.md)) | A small HTTP convention for *writing* a `did:vh` log to a host (`did:vh` itself only specifies reading). No accounts, no tokens: the log's own validity is the authorization. A `did:web` document is published beside every log, derived from it, for clients that only speak `did:web`. |
| **hosts** (`server/host/`) | did.md's host (`identity-host.ts`), and `byo-host.ts`, an independent one-domain file host. Both pass the shared conformance core. |
| **libraries and CLI** (`packages/`) | `Identity` (create, open, update, rotate, give it a place, publish, unpublish) without a DOM, and `dito`, a CLI for people, scripts and agents. |

The wallet speaks only the protocol and the host only has to implement it, so either side can be a
third party's.

## Quick start

Requires Node.js >= 26 and [pnpm](https://pnpm.io).

```sh
pnpm install
pnpm test                           # vitest
pnpm build:home                     # -> dist/index.html (the whole wallet, one file)
node scripts/dev-static-server.ts   # serve dist/ on http://127.0.0.1:8788
pnpm astro:dev                      # the Astro + React site (web/), separate from the wallet build
```

TypeScript runs directly on Node (type stripping, no loader), so sources use erasable syntax only: no
parameter properties, enums or namespaces (`erasableSyntaxOnly` enforces this). pnpm is the only package
manager; there is no other runtime.

### The CLI

```sh
pnpm dito new                                   # creates ./did.jsonl (a did:vh with no host yet), prints the mnemonic once
pnpm dito show                                  # DID, locations, document (no secret needed)
pnpm dito verify <did:vh:…> --watcher https://did.md   # fetch and validate a published log (a did:vh names no host)
pnpm dito forget <did:vh:…>                     # forget the newest version verify/fetch remember (see `dito --help`)
DITO_MNEMONIC="…" pnpm dito connect alice       # host it at https://alice.did.md (or --domain)
GITHUB_TOKEN=… DITO_MNEMONIC="…" pnpm dito github   # host it on <login>.github.io
DITO_MNEMONIC="…" pnpm dito rotate
DITO_MNEMONIC="…" pnpm dito service add '#files' relativeRef https://alice.example/
```

`--json` prints one JSON object per command. The mnemonic is never written to disk by the tool
(`DITO_MNEMONIC`, `--mnemonic-file`, or a prompt).

### As a library

```ts
import { Identity } from "./packages/wallet/src/identity.ts";

const { identity, mnemonic } = await Identity.create();   // a did:vh DID, no host yet
await identity.connect({ username: "alice", domain: "did.md" });   // one update entry; the DID does not change
await identity.rotate();

// anywhere else: the mnemonic plus the public log are the whole identity
const same = await Identity.fromSource({ mnemonic, src: "https://alice.did.md" });
```

Local state only advances after the host accepted the write.

## Keys

One BIP-39 phrase (24 words, 256-bit entropy) feeds SLIP-0010 Ed25519 hardened derivation:

```text
m/0'       Root key, and the genesis Sign key
m/1'/n'    pre-rotation key for generation n
```

Every update is signed by the key the previous entry committed to and commits the next one, so a
compromised current Sign key reveals neither the phrase nor any future key. The phrase is the only
backup; it is never sent anywhere. By default nothing secret is stored in the browser; a PRF-capable
passkey can optionally seal the phrase locally (a convenience copy, not a replacement for the backup).

## Hosting

Any conforming host works; the wallet derives every URL from the location the identity's own document names.

```sh
pnpm start:identity                                     # a did.md-style host on 127.0.0.1:8787
pnpm conformance --domain example.com                   # check any host (throwaway identities)
pnpm conformance --domain did.md --base http://127.0.0.1:8787   # a local host standing in for the domain
```

- **Your own GitHub Pages** (`<login>.github.io`) is a supported host that needs no server.
- Public reads are ~all the traffic and cacheable, so the host sends
  `Cache-Control: public, max-age=0, s-maxage=30` on them (never on `404`s or writes); put a CDN in
  front and the origin only sees cache misses and writes.
- To write a host of your own, start from `createByoHost()` in `server/host/byo-host.ts`:
  a complete `(Request) => Response` handler for one domain, built only on `packages/vh`.

## Repository

```text
client/, public/, build.ts   the wallet (single-file build, esbuild)
web/, astro.config.mjs       Astro + React site (own srcDir/outDir; does not touch the wallet build)
packages/vh/                 did:vh: log verification and creation, signing keys and proofs, the hosting client, conformance, the did:web shadow
packages/wallet/             the wallet profile: Master-seed keys, Identity, host adapters, GitHub Pages, backups
packages/cli/                `dito`
packages/did-verify/         JWT / id_token verification (embedded JWK or a did:vh kid, from the verifier's watchers)
server/host/                 the did.md host (identity-host.ts, http-server.ts) and byo-host.ts (one-domain file host)
server/serve.ts              fetch-style HTTP server on node:http; host-fetch.ts: fetch that honors a Host header
server/oauth/                OAuth 2.0 / OID4VP convenience layer and an OIDC bridge
tests/                       everything above, end to end
```

See [ARC.md](ARC.md) for how the pieces fit.

## Build and deploy

`pnpm build:identity`, `build:bridge` and `build:byo` bundle each server with esbuild into a single
`dist/*.mjs` that runs with plain `node` (>= 26). `deploy.sh [all|client|bridge|identity|byo]` ships them
to the VPS, where systemd units start them with `/usr/bin/node`.

## Notes

- **`did:vh`** (a pre-draft by Stephen Curran, built on VH-Log) is implemented in `packages/vh`, pinned by shared
  test vectors (`packages/vh/vectors/`) that an independent verifier in another repository is checked against. A
  `did:vh:<SCID>` names no host; the identity's own signed document says where its log is published (`alsoKnownAs`),
  so the DID never changes when the log moves. Witnesses are not supported: a log that configures any is refused.
- **Cryptography.** The log proof is Ed25519 with `eddsa-jcs-2022`. Swapping in a post-quantum
  signature would make logs non-conformant; PQ belongs in separately versioned DID Document use cases
  (for example an ML-KEM key agreement key) or in a future method version.
- **OpenID Connect.** The optional `server/oauth/` layer turns a wallet's self-issued, DID-signed
  `id_token` into standard OIDC for relying parties that cannot verify DIDs themselves.

## License

[AGPL-3.0-only](LICENSE).
