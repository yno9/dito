# packages

| package | what it is |
|---|---|
| `webvh/` | Generic did:webvh toolkit, incl. the [Hosting Protocol](../SPEC-webvh-hosting.md) client, conformance suite and a reference server: a thin typed layer over [`didwebvh-ts`](https://github.com/decentralized-identity/didwebvh-ts). Ed25519 signer, `createLog` / `updateLog` / `resolveLog`, Data Integrity proofs, strict DID -> `did.jsonl` URL, `resolveDidWebvh()`. Nothing dito-specific. |
| `wallet/` | The wallet profile on top: Master-seed keys (mnemonic, SLIP-0010, permanent pre-rotation), hosting adapters (did.md, GitHub Pages), wallet credentials, and the DOM-free `Identity` session. |
| `cli/` | `pnpm dito <command>`: the same operations from a terminal, a script or an agent. |
| `did-verify/` | JWT/id_token verification for the OIDC bridge (embedded JWK or a did:webvh `kid`). |

## Identity, in code

```ts
import { Identity } from "./packages/wallet/src/identity.ts";

const { identity, mnemonic } = await Identity.create();   // provisional DID, no host
await identity.connect({ username: "alice" });             // -> https://alice.did.md
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

The wallet (`Identity`, the dashboard) only speaks [webvh-hosting/1](../SPEC-webvh-hosting.md); the host only
has to. To check a server: `pnpm conformance --domain <its-domain> [--base http://127.0.0.1:PORT]`.
To start one: `createReferenceHost()` in `packages/webvh/src/reference-host.ts` is a complete `(Request) => Response`
handler on top of didwebvh-ts.
