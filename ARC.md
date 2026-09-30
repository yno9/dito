# Architecture

What dito is today and how the parts fit. (Protocol details: [SPEC-webvh-hosting.md](SPEC-webvh-hosting.md).)

## 1. Positioning

- dito is a **Universal Digital Identity (UDI) wallet**, not an EUDI wallet. It keeps the OpenID4VC
  protocol family (SIOPv2 self-issued `id_token`, OID4VP, VC-DM 2.0) and replaces the state-accredited
  trust anchor with a self-sovereign `did:webvh` identity: the trust root is a self-signed, verifiable log.
- did:webvh handling is not the differentiator, so **all did:webvh log mechanics go through
  [`didwebvh-ts`](https://github.com/decentralized-identity/didwebvh-ts)** (create, update, portability move,
  validation, resolution). What is ours: the key profile, hosting, and the wallet.
- Client and host are separable. The wallet is a generic did:webvh wallet; a host is anything that
  implements `webvh-hosting/1`. Either can be replaced by a third party, and a conformance suite
  says whether a host qualifies.

```
                  ┌──────────── wallet (browser, CLI, library) ────────────┐
                  │  keys (one mnemonic) · Identity · did:webvh via        │
                  │  didwebvh-ts · webvh-hosting/1 client                  │
                  └───────────────┬───────────────────────────┬────────────┘
      GET/PUT/POST/DELETE did.jsonl│                          │ OAuth / OID4VP (optional)
                  ┌───────────────▼───────────┐   ┌──────────▼───────────┐
                  │ any webvh-hosting/1 host  │   │ relying party (RP)   │
                  │ did.md · reference host · │   │ resolves the DID     │
                  │ <login>.github.io         │   │ itself                │
                  └───────────────────────────┘   └──────────────────────┘
```

## 2. Principles

- The DID's job is to prove control, nothing else.
- A host keeps only the public log (and what it derives from it). It is stateless otherwise.
- Private keys exist only in the wallet, in memory, and are never sent anywhere.
- Authorization to change a log is the log itself (a valid extension signed by an authorized key). No accounts, no tokens.
- The RP owns its own capability types and queries; the host verifies generically.
- Read paths are cacheable and never need the host's CPU; only writes do.

## 3. Packages

| path | role |
|---|---|
| `packages/webvh/` | Generic layer over `didwebvh-ts`: `Ed25519Signer`, `createLog` / `updateLog` / `resolveLog`, Data Integrity proofs, strict DID→URL parsing (`parseDid`, `didToLogUrl`), `resolveDidWebvh()`, the hosting **client** (`WebvhHostingClient`), the **conformance suite**, and a **reference host**. Nothing dito-specific. |
| `packages/wallet/` | The wallet profile: Master-seed keys (BIP-39, SLIP-0010, permanent pre-rotation), portability moves, host adapters (any `webvh-hosting/1` host, GitHub Pages), backups, and `Identity`, the DOM-free session used by the CLI and scripts. |
| `packages/cli/` | `dito`, the same operations from a terminal, a script or an agent (`--json`). |
| `packages/did-verify/` | JWT / `id_token` verification for the OIDC bridge (embedded JWK or a `did:webvh` `kid`); resolves the whole log before trusting a document. |
| `client/`, `public/`, `build.ts` | The browser wallet, bundled into a single `dist/index.html` (inline script and styles) that also runs from `file://`. |
| `server/host/` | did.md's host: `identity-host.ts` (the protocol, plus the authentication-key resolution the OAuth layer uses) and `http-server.ts` (the process). |
| `server/oauth/` | The optional OAuth 2.0 / OID4VP convenience layer and an OIDC bridge (`src/`). |

## 4. did:webvh, and where we keep a guard

- Logs are created, updated, moved and validated by `didwebvh-ts`. `packages/webvh/src/log.ts` is the only
  place the rest of the code touches it, so its API stays contained.
- `didwebvh-ts@2.8.0` accepts a log entry whose `proof` is an empty array. `resolveLog()` and the host's
  `validateLogAt()` therefore each independently require an authorized proof on every entry.
- The library does not export the DID→URL rule, so `packages/webvh/src/url.ts` keeps one strict
  implementation (FQDN-only, no IP literals, no encoded path tricks) used by every fetcher, which is also the
  SSRF guard.
- The did:web mirror (`did.json`) is `generateParallelDidWeb` plus an atproto-shaped post-process.

## 5. Keys and the wallet

- **One phrase, deterministic keys.** 24-word BIP-39 → SLIP-0010 Ed25519: `m/0'` Root (and genesis Sign key),
  `m/1'/n'` pre-rotation key of generation n. Every update consumes the committed key and commits the next.
- **Provisional genesis.** Create builds a portable log (`did:webvh:<SCID>:ex.alias`) entirely in the browser;
  nothing is published. Choosing a host appends a signed portability entry (the old DID stays in
  `alsoKnownAs`) and writes the full log there. A host is a place that validates and serves a signed log, not the
  issuer of the identity.
- **Identity Container.** A password-encrypted JWE (`PBES2-HS512+A256KW` + `A256GCM`) with a manifest and the
  logical files (`did.jsonl`, keyring, device bindings, grants) is the offline backup. Passkey and DPoP private
  keys, tokens and live capabilities are never included.
- **State model.** *loaded* (persisted in this browser) vs *unloaded*; *locked* (secrets only as ciphertext, the
  default, always after a reload) vs *unlocked* (decrypted in memory for a signing action; a locked action opens the
  inline passphrase field and resumes afterwards); *connected* vs *disconnected* (whether the host currently
  serves the log; disconnecting is a temporary withdrawal, not deactivation).
- **Single file.** `dist/index.html` has no external script or module. It talks to hosts that allow the
  `null` origin (`file://`).

## 6. Hosting

`webvh-hosting/1` (see the spec): `GET/PUT/POST/DELETE did.jsonl`, `PUT did-witness.json`, a disconnect request
signed by a current update key, an error table, permissive CORS, an optional `/.well-known/did-hosting.json`.

- **Conformance.** `packages/webvh/src/conformance.ts` is the executable spec (`bun run conformance`). did.md's
  host and the independent reference host both pass it, and the unmodified wallet works against the reference host.
- **Caching.** Reads carry `Cache-Control: public, max-age=0, s-maxage=30`; `404`s and writes are never cached; a
  writer bypasses the cache with `?_=<time>`. Behind a CDN the origin sees only misses and writes.
- **Topologies.** did.md runs `server/host/http-server.ts` (one process, local disk) behind a reverse proxy and a
  CDN. A user can instead host on their own `<login>.github.io` (no server; writes take the Pages build time to appear).
  Any other conforming host works the same.

## 7. Authentication and authorization (the optional OAuth layer)

The essential core is the host plus identity resolution. `server/oauth/` is optional plumbing for RPs without
a backend of their own; the core never imports it.

- **Identity layer**: `identity-host.ts` resolves a verification method from the DID's published `authentication` array
  (any fragment, not just `#pass-1`) and verifies by the proof's `cryptosuite` or the token's `alg`. Only Ed25519 /
  `eddsa-jcs-2022` is implemented; other values are rejected explicitly.
- **Authorization layer**: capability types belong to the RP (a namespaced type name and a JSON Schema the RP
  owns). The host only checks that the type is a namespaced string and that a valid Data Integrity proof by the DID's
  authentication key covers it.
- **Transport**: the wallet talks to the OAuth layer with an OID4VP `vp_token` carrying a minimal VC-DM 2.0
  capability; RPs see a plain OAuth 2.0 `code` + PKCE exchange.
- **RP authentication**: either dynamic client registration (RFC 7591), or a JWT-secured authorization
  request (RFC 9101) signed by the RP's own `did:webvh` key, with the redirect URI checked against the RP's own DID
  document. The wallet and the server both verify independently, and the server accepts RP DIDs only from an allow-listed
  set of domains (fail-closed; SSRF).
- **OIDC bridge**: turns a wallet's self-issued `id_token` into standard OIDC claims for RPs that cannot verify
  DIDs (Forgejo, Outline, …). `sub` is the stable SCID.

## 8. Known gaps

- Logs that use witnesses resolve in the CLI, `Identity.fromDid` and `resolveDidWebvh`; the dashboard's own log
  fetch does not fetch `did-witness.json` yet.
- A disconnect request can be replayed for its 5-minute window (a nonce would tighten it).
- The dashboard's Connect field takes `name.domain`; path-based locations work in the library and reference host only.
- The W3C Digital Credentials API and CHAPI are deliberately not used: an in-browser JS wallet cannot register as an
  OS credential provider, so "connect with [wallet]" stays an explicit, static directory.
- Interoperability with other UDI wallets is only tested against mocks, since none exist yet.
