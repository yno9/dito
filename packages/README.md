# packages

| package | what it is |
|---|---|
| `vh/` | did:vh, and nothing dito-specific: log verification (every entry, in order), creation, update and deactivation, the strict web-location parser and fetcher, the did:web shadow derivation, Ed25519 keys and Data Integrity proofs (`eddsa-jcs-2022`), the version memory (refuse an old or forked log), the [Hosting Protocol](../SPEC-vh-hosting.md) client and its conformance suite. No external DID library. |
| `wallet/` | The wallet profile on top: Master-seed keys (mnemonic, SLIP-0010, permanent pre-rotation), hosting adapters (did.md, GitHub Pages), wallet credentials, and the DOM-free `Identity` session (a did:vh identity). |
| `cli/` | `pnpm dito <command>`: the same operations from a terminal, a script or an agent. |
| `did-verify/` | JWT/id_token verification for the OIDC bridge (embedded JWK or a did:vh `kid`, from the verifier's watchers). |

## Identity, in code

```ts
import { Identity } from "./packages/wallet/src/identity.ts";

const { identity, mnemonic } = await Identity.create();   // a did:vh DID, no host yet
await identity.connect({ username: "alice" });             // -> https://alice.did.md; the DID stays
await identity.publishUpdate(doc => ({ ...doc, service: [...doc.service, { id: "#x", type: "X", serviceEndpoint: "https://…" }] }));
await identity.rotate();

// later, anywhere: the mnemonic + the public log are the whole identity
const same = await Identity.open({ mnemonic, log: await (await fetch(url)).text() });
```

Local state only advances after the host accepted the write.

## CLI

```
pnpm dito new                       # writes ./did.jsonl, prints the mnemonic once
pnpm dito show | verify [file|url]  # public: no secret needed
DITO_MNEMONIC="…" pnpm dito connect alice
GITHUB_TOKEN=… DITO_MNEMONIC="…" pnpm dito github
pnpm dito service add '#files' relativeRef https://alice.example/ --mnemonic-file m.txt
pnpm dito rotate | unpublish
```

`--json` prints one JSON object per command (agents). The mnemonic is never written to disk by the tool.

## Swapping either side

The wallet (`Identity`, the dashboard) only speaks [vh-hosting/1](../SPEC-vh-hosting.md); the host only
has to. To check a server: `pnpm conformance --domain <its-domain> [--base http://127.0.0.1:PORT]`.
To start one: `createByoHost()` in `server/host/byo-host.ts` is a complete `(Request) => Response`
handler for one domain, on top of `packages/vh`.
