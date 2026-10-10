# dito

**A generic `did:webvh` wallet, an open hosting protocol for `did:webvh` logs, and a reference host.**

Every identity is yours to dispose of: to use, or to walk away from. You keep the keys; hosts only
publish a signed log, and any host can be swapped for another without asking anyone.

| | what it is |
|---|---|
| **dito** (`client/`, `public/`) | The wallet: one self-contained `index.html` you can also open from disk. One 24-word passphrase, deterministic keys, permanent pre-rotation. Private keys never leave the browser. |
| **webvh-hosting/1** ([SPEC-webvh-hosting.md](SPEC-webvh-hosting.md)) | A small HTTP convention for *writing* a `did:webvh` log to a host (`did:webvh` itself only specifies reading). No accounts, no tokens: the log's own validity is the authorization. |
| **hosts** (`server/host/`, `packages/webvh/src/reference-host.ts`) | did.md's host, and an independent ~150-line reference host. Both pass the same conformance suite. |
| **libraries and CLI** (`packages/`) | `Identity` (create, open, update, rotate, move, publish, unpublish) without a DOM, and `dito`, a CLI for people, scripts and agents. |

The wallet speaks only the protocol and the host only has to implement it, so either side can be a
third party's.

## Quick start

Requires Node.js >= 26 and [pnpm](https://pnpm.io).

```sh
pnpm install
pnpm test                      # ~115 tests
pnpm build:home               # -> dist/index.html (the whole wallet, one file)
node scripts/dev-static-server.ts   # serve dist/ on http://127.0.0.1:8788
```

### The CLI

```sh
pnpm dito new                                   # creates ./did.jsonl, prints the mnemonic once
pnpm dito show                                  # DID, host, document (no secret needed)
pnpm dito verify <did:webvh:…>                  # fetch and validate a published log
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

const { identity, mnemonic } = await Identity.create();   // provisional DID, no host yet
await identity.connect({ username: "alice", domain: "did.md" });
await identity.rotate();

// anywhere else: the mnemonic plus the public log are the whole identity
const same = await Identity.fromDid({ did: identity.did, mnemonic });
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

Any conforming host works; the wallet derives every URL from the DID.

```sh
pnpm start:identity                                     # a did.md-style host on 127.0.0.1:8787
pnpm conformance --domain example.com                   # check any host (throwaway identities)
pnpm conformance --domain did.md --base http://127.0.0.1:8787   # a local host standing in for the domain
```

- **Your own GitHub Pages** (`<login>.github.io`) is a supported host that needs no server.
- Public reads are ~all the traffic and cacheable, so the host sends
  `Cache-Control: public, max-age=0, s-maxage=30` on them (never on `404`s or writes); put a CDN in
  front and the origin only sees cache misses and writes.
- To write a host of your own, start from `createReferenceHost()` in `packages/webvh/src/reference-host.ts`:
  a complete `(Request) => Response` handler built only on `didwebvh-ts`.

## Repository

```text
client/, public/, build.ts   the wallet (single-file build)
packages/webvh/              generic did:webvh layer over didwebvh-ts, hosting client, conformance, reference host
packages/wallet/             the wallet profile: Master-seed keys, host adapters, Identity, backups
packages/cli/                `dito`
packages/did-verify/         JWT / id_token verification (embedded JWK or a did:webvh kid)
server/host/                 the did.md host (identity-host.ts, http-server.ts)
server/oauth/                OAuth 2.0 / OID4VP convenience layer and an OIDC bridge
tests/                       everything above, end to end
```

See [ARC.md](ARC.md) for how the pieces fit.

## Notes

- **`didwebvh-ts`** does all the `did:webvh` log work (create, update, portability, validation). We keep
  a guard for one gap: version 2.8.0 accepts an entry whose `proof` is an empty array, so `resolveLog()`
  and the host reject that themselves.
- **Cryptography.** The v1.0 log proof is Ed25519 with `eddsa-jcs-2022`. Swapping in a post-quantum
  signature would make logs non-conformant; PQ belongs in separately versioned DID Document use cases
  (for example an ML-KEM key agreement key) or in a future method version.
- **OpenID Connect.** The optional `server/oauth/` layer turns a wallet's self-issued, DID-signed
  `id_token` into standard OIDC for relying parties that cannot verify DIDs themselves.

## License

[AGPL-3.0-only](LICENSE).
