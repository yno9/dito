# did:webvh Hosting Protocol (webvh-hosting/1)

Status: draft, implemented by did.md's host (`server/host/identity-host.ts`) and by dito's generic
client (`packages/webvh/src/hosting.ts`). Written so that **any client can talk to any server**:
a third-party wallet must work against did.md's server, and dito must work against a third-party
server that implements this document. `packages/webvh/src/conformance.ts` is the executable
form of this text; a server that passes it is a conforming server.

## 0. Why this exists

[did:webvh] defines how a DID log is *read*: fetch `did.jsonl` over HTTPS and verify it. It
deliberately says nothing about how a controller *puts* the log there (FTP, git, S3, a control
panel...). A wallet that wants to publish, update, move and take down a DID on a host it
does not own needs one small, boring convention. This is that convention.

Design rules:

1. **No accounts, no tokens.** The authorization to change a log is the log itself: a write is
   accepted iff the resulting log is a valid did:webvh log that extends the current one. The
   only other authorized act, taking the log down, is a request signed by a current update key.
2. **Clients derive every URL from the DID**, exactly as a resolver does. A client never needs
   to know which server it is talking to.
3. **The server is a validating file host.** Anything beyond that (naming policy, quotas,
   mirrors, extra resources) is the server's business and must not be required by clients.
4. Browser clients are first-class (CORS is part of the protocol).

Key words MUST, SHOULD, MAY are used as in RFC 2119.

## 1. Resources

For a DID `did:webvh:<scid>:<host>[%3A<port>][:<path>...]` the *base* is

```
https://<host>[:<port>]/.well-known/            (no path segments)
https://<host>[:<port>]/<path>/.../             (with path segments)
```

(exactly [did:webvh]'s DID-to-URL rule). Resources under the base:

| resource | methods | meaning |
|---|---|---|
| `did.jsonl` | GET, PUT, POST, DELETE | the DID log, one JSON entry per line, each line ending in `\n`; `text/jsonl` |
| `did-witness.json` | GET, PUT | witness proofs, a JSON array of `{ "versionId", "proof": [...] }` |
| `did.json` | GET | OPTIONAL: the parallel `did:web` document, derived by the server, never writable |

A server MAY serve other resources next to these; a client MUST NOT depend on them.

## 2. Reading

`GET <base>did.jsonl` -> `200` with the log, or `404` when nothing is published. Responses
carry `Access-Control-Allow-Origin: *` and SHOULD NOT be cached by intermediaries for longer than
the log's `ttl` (servers SHOULD send `Cache-Control: no-cache`). Same for `did-witness.json` and `did.json`.

## 3. Writing

All write bodies are limited by the server (recommended minimum: 16 MiB for `did.jsonl`,
1 MiB for anything else). A server MUST validate before it stores anything and MUST store
atomically: after any response the resource is either entirely the old value or entirely the new one.
Writes to one DID MUST be serialized.

### 3.1 `PUT did.jsonl` - publish or replace the whole log

Body: the complete log.

* If nothing is published at this location, the body is accepted iff it is a valid did:webvh log
  (all of [did:webvh]'s verification: SCID, entry hashes, proofs by authorized update keys,
  pre-rotation, portability) **whose current `state.id` designates this location**. Response `201`.
  (Whoever publishes first owns the location; see Security.)
* If a log exists, the body MUST preserve it as a **byte-for-byte prefix** and be valid. Response `204`.
  This is what makes a portability move (which appends an entry) and a republish safe without any credential.

### 3.2 `POST did.jsonl` - append entries

Body: one or more entries (not a genesis entry). The result (existing log + body) must be
valid. Response `204`. Requires an existing log.

### 3.3 `PUT did-witness.json`

Body: the witness file. When a log exists it must remain valid with the new witness file
(future proofs may be uploaded before their entry). Response `204`.

### 3.4 `DELETE did.jsonl` - take the DID down

Removes the log and every derived resource (`did-witness.json`, `did.json`), leaving the
location free. did:webvh permits removing the log as a way to signal deactivation; the same
controller MAY republish later.

Body (`application/json`): a *disconnect request*

```json
{
  "did": "<the DID currently published here>",
  "proof": {
    "type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "did:key:<k>#<k>",
    "created": "<ISO 8601 UTC>", "proofValue": "z..."
  }
}
```

`proof` is computed per [Data Integrity EdDSA / eddsa-jcs-2022] over the request **without**
`proof`, with `<k>` one of the log's *current* `updateKeys`. The server MUST check that
`did` equals the DID the log currently states, the signature, and that `proof.created` is within
5 minutes of the server's clock. Response `204`; `404` if nothing is published.

### 3.5 Errors

Every non-2xx response has a `text/plain` body that says why (for humans and logs).

| status | when |
|---|---|
| 400 | body is not a valid log / request; chain does not extend the existing log; proof missing or wrong; stale disconnect proof |
| 403 | valid request refused by server policy (reserved name, not permitted, quota) |
| 404 | nothing published (GET, DELETE) |
| 405 | method not allowed on this resource (e.g. writing `did.json`) |
| 409 | OPTIONAL alternative to 400 for "does not extend the existing log" |
| 413 | body too large |
| 429 | rate limited |

Clients MUST treat any non-2xx response as failure, show the body, and MUST NOT retry a `4xx` blindly.

## 4. CORS

Authorization never depends on the caller's origin or on cookies, so a server MUST NOT use
either. To let browser wallets from any origin work, responses to `did.jsonl` and
`did-witness.json` (reads and writes) SHOULD carry `Access-Control-Allow-Origin: *`, and the
preflight (`OPTIONS`) MUST allow methods `GET, POST, PUT, DELETE, OPTIONS` and header
`content-type`.

## 5. Capability document (optional)

`GET https://<host>/.well-known/did-hosting.json` (note: at the host root, not at a DID base)

```json
{
  "protocol": "webvh-hosting/1",
  "writes": true,
  "delete": true,
  "witness": true,
  "maxLogBytes": 16777216
}
```

All members but `protocol` are OPTIONAL; a missing member means "not stated". Clients use it to
tell "this host speaks the protocol" from "unknown" before attempting a write, and to explain a failure.
A host that serves it MUST NOT lie: `writes: true` means `PUT did.jsonl` for a fresh valid log may succeed.

## 6. Availability

A location is free iff `GET <base>did.jsonl` is `404`. There is no separate availability endpoint in
the protocol; a server MAY offer one as an extension.

## 7. Client behaviour (normative for clients)

* **Publish a new identity:** derive the base from the (moved) DID; `PUT` the full log.
* **Publish a change:** `POST` the new entry (or `PUT` the full log). On `400` (chain mismatch) fetch the
  log and reconcile before retrying.
* **Move to another host:** append a portability entry (`alsoKnownAs` keeps the old DID), `PUT` the full
  log at the *new* location, then (best effort) `DELETE` at the old one.
* **Verify what was written:** `GET` it back and validate it; do not trust `2xx` alone.
* Never send a secret: no request carries a key, a passphrase or a bearer token.

## 8. Security considerations

* **Squatting.** The first valid log at a location wins. Servers that need something stronger
  (per-user quotas, reserved names, email/OIDC login before the first `PUT`) enforce it as policy
  (`403`), outside this protocol; clients treat `403` as final.
* **Replay of a disconnect request** is possible for 5 minutes; it can only ever delete what the
  same key already controlled, and the controller can republish. Servers MAY keep seen
  `proofValue`s for the window.
* **Availability of the log** is the host's responsibility: hosts can go away, which is why did:webvh is
  portable. Clients SHOULD keep their own copy of the log.
* **SSRF.** Anything that fetches a log from a DID (resolvers, this client's `probe`) MUST apply
  the strict DID parsing of `packages/webvh/src/url.ts` (fully-qualified DNS name, no IP literals, no
  encoded path tricks) before it builds a URL.
* All traffic is HTTPS; plain HTTP is for local development only.

## 9. Conformance

`packages/webvh/src/conformance.ts` exports `runConformance(target)`; `bun run conformance` runs it
against a URL. It creates throwaway identities and checks sections 2-6. did.md's own server is in
CI against it (`tests/hosting-conformance.test.ts`).

## 10. Relation to did.md

did.md's server is the reference implementation. Its extras are *not* part of this protocol:
`routing.json`, the `atproto-did` handle resource, the OAuth/OID4VP endpoints, and the
`/v1/availability` helper.

[did:webvh]: https://identity.foundation/didwebvh/v1.0/
[Data Integrity EdDSA / eddsa-jcs-2022]: https://www.w3.org/TR/vc-di-eddsa/
