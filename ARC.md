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
| `client/`, `public/`, `build.ts` | The browser wallet, bundled by esbuild into a single `dist/index.html` (inline script and styles) that also runs from `file://`. |
| `web/`, `astro.config.mjs` | An Astro + React site with its own `srcDir`, `publicDir` and `outDir` (`build/astro`), so it cannot collide with the wallet's `public/` and `dist/`. |
| `server/host/` | did.md's host: `identity-host.ts` (the protocol, plus the authentication-key resolution the OAuth layer uses) and `http-server.ts` (the process); `byo-host.ts` is the one-domain file host behind digitalcommons.jp. `server/serve.ts` adapts a `(Request) => Response` handler to `node:http`; `server/host-fetch.ts` is a `fetch` that honors a caller-set `Host`, which Node's own fetch overrides and the Host-routed host and its tests need. |
| `server/oauth/` | The optional OAuth 2.0 / OID4VP convenience layer and an OIDC bridge (`src/`). |

### 3.1 Runtime and tooling

- **Node.js >= 26, pnpm only.** Sources run as-is on Node's type stripping (no transpile step, no loader), so
  they use erasable TypeScript only; `erasableSyntaxOnly` rejects parameter properties, enums and namespaces.
  Route modules stay `(Request) => Response`, which keeps them runtime-neutral (the identity host also
  type-checks against Cloudflare Workers; it reads env through `globalThis.process`).
- **Tests** are vitest. Tests that need a server spawn it as a child `node` process (`tests/spawn.ts`).
- **Builds** are esbuild: the wallet into one HTML file, each server into one `dist/*.mjs`. Nothing is
  compiled to a native binary; the VPS runs the bundles with `/usr/bin/node` under systemd.
- **Deploy** is `deploy.sh [all|client|bridge|identity|byo]`. systemd units are managed on the host; the
  script replaces bundles and health-checks, restoring the previous bundle on failure.

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

- **Conformance.** `packages/webvh/src/conformance.ts` is the executable spec (`pnpm conformance`). did.md's
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
  and verifies by the proof's `cryptosuite` or the token's `alg`. Which method may sign the user in is `maySignIn`
  (`packages/webvh`), shared with `did-verify`: on a did.md identity (its `authentication` includes the Root key `#pass-1`)
  only the Root may -- other authentication keys there were added for relying parties (a messaging app's DID Rotation
  signing key, say) and must not act as the user everywhere. A document without `#pass-1` is another wallet's, whose key
  names are not assumed (PLAN1): any of its authentication methods may. Only Ed25519 /
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

### 7.1 SIOPv2 / OpenID4VP direct sign-in (a relying party with no key of its own)

The wallet is a plain SIOPv2 wallet; the OAuth layer above exists only for RPs that want OAuth (the OIDC bridge). An app such as
biset speaks SIOPv2/OpenID4VP and nothing else, and the server is never asked anything.

- **Request** (`/authorize`, parsed by `siopAuthorizationParameters` in `client/app.ts`, unsigned, strict key list):
  `client_id=redirect_uri:<callback>` (OID4VP 1.0 §5.9.3: the RP *is* its redirect URL), `response_type=vp_token id_token`,
  `response_mode=fragment`, `scope=openid`, `nonce`, `state`, `dcql_query` (one credential, `id: "capability"`, its type in
  `meta.type_values`), `transaction_data` (§8.4, base64url JSON items, each naming `credential_ids: ["capability"]`) and
  `client_metadata`. Transaction data types: `device_capability` (`device_jkt`, `scope[]`) and `did_document_edit` (`detail` =
  the document-edit object). **An unknown type is refused** (§5.1). `https:` callbacks only, except a Tor hidden service (`http://<56 chars>.onion/…`).
- **Who is asking**: the callback host, always. `client_metadata.rp_did` is believed only when that DID's own document lists the
  callback as a `SIOPRedirectTarget` service endpoint; then the app's name is shown and approvals are grouped by that DID
  (the card list for "applications"). Otherwise it is ignored.
- **Response** (fragment): `vp_token={"capability":[<VP>]}` and `id_token`, plus `state`; no `iss` (that is OAuth, RFC 9207). The VP
  holds the capability VC and is signed by the Root key with `challenge = nonce`, `domain = client_id` (so it cannot be replayed to
  another verifier); the `id_token` is self-issued (`iss = sub =` the DID, `aud = client_id`, the `nonce`).
- **Wallet discovery**: an identity's DID document lists `{ id: "#wallet", type: "SelfIssuedOPAuthorizationEndpoint",
  serviceEndpoint: <its authorize URL> }` (written at creation). An app finds the wallet from the DID document alone.
- The embedded frame and the create flow accept the same request (`validEmbedLogin`, `embedApprovalFor`).

## 8. Known gaps

- Logs that use witnesses resolve in the CLI, `Identity.fromDid` and `resolveDidWebvh`; the dashboard's own log
  fetch does not fetch `did-witness.json` yet.
- A disconnect request can be replayed for its 5-minute window (a nonce would tighten it).
- The dashboard's Connect field takes `name.domain`; path-based locations work in the library and reference host only.
- The W3C Digital Credentials API and CHAPI are deliberately not used: an in-browser JS wallet cannot register as an
  OS credential provider, so "connect with [wallet]" stays an explicit, static directory.
- Interoperability with other UDI wallets is only tested against mocks, since none exist yet.
- The create form's confirm step is a real form submit (a password manager only offers to save on one, §9), but the
  Passphrase does not leave: a `formdata` listener drops the `password` entry as the browser builds the request body
  (the manager reads the field's value from the page, not from the request), so the POST (or a file:// GET) carries
  the account name only. Checked on the wire for both the standalone and the embedded forms. Keep that listener.

## 9. Password-manager autosave: what makes it fire

The create form exists so a password manager (Proton Pass is the one we test with) offers to save the generated
Passphrase. It has broken several times and cost days each time, because the detector is a fuzzy classifier and the
symptom is only "no dialog". This section is the checklist. Verified 2026-10-11 against Proton Pass' sources
(`ProtonMail/WebClients`, `applications/pass-extension`; detector `@protontech/autofill` 0.0.38040317) and by
experiment in the browser. Rules can change with an extension update; when it stops firing, start at 9.6.

### 9.1 What the manager needs

| Need | Detail |
|---|---|
| Top-level frame | Sub-frames only get manual prompts: nothing autosaves from an iframe. The biset embed (PLAN-embedded-wallet.md) can never trigger it; the save happens in a top-level wallet page of the same tab (9.4). |
| A password input it recognises | A real, **visible** `<input type="password">` (the detector treats a field below roughly 30×15 px as invisible), in a `<form>` or alone. Not `readonly`, `disabled`, `aria-disabled` or `aria-busy`. |
| A form that is not "busy" | The form, its buttons, its fields and **every ancestor** are checked for those four attributes at submit time. A single `readonly` field (the old overlay `<textarea>`) is enough. |
| No decoy inputs | A `type="text"` input that is offscreen, tiny, transparent or `readonly` is flagged invisible and skews the form's classification. With the old offscreen username and the overlay textarea in the form it stopped firing; removing the username plus either the textarea or the Alias field brought it back. `data-protonpass-ignore` on those fields did not bring it back; a visible text "username" stopped it firing; a 1 px transparent one fired but saved an empty username. |
| An account name | `<input type="hidden" name="username" value="…">`: `name` or `id` containing `user`, `login`, `email` or `identifier`; value non-empty, at most 320 characters, not `0`/`1`/`true`/`false`. It must hold a value **when the detector scans**; the value is read again when the form is submitted, so it can be edited in place afterwards (replacing the element made the detector lose the form). A hidden input is the only way that gave a saved username; a text input gave an empty one. Priority in Pass' `getFormData`: a visible username field, then an email field, then the hidden username. |
| A real submit gesture | The user's own click on a submit button, or Enter, fires the form's `submit` event; that is what we verified. Whether a script-made click would also count is untested, so the confirm button is always the user's click. (Create itself may be a script click: it only persists locally.) |
| A recognised submission | A navigation: POST or GET both fired for the final form (a plain form fired for POST and not for GET, so POST is the safe one). Or a script submit that removes the form **at least 250 ms after** the click or Enter; sooner and Pass discards it as a misread Cancel. |
| A server answer | The request must succeed. `file_server` answers a POST with 405, so Caddy rewrites it to a GET (see `method @post GET` in the Caddyfile). |
| Pass itself | Unlocked, autosave on, the site not set to "never ask", a writable vault, and no existing item with the same domain, username and password (that suppresses the dialog). `data-protonpass-autosave-ignore` on a form turns autosave off. |

### 9.2 Do not remove or change (the create form)

In `client/pages/creation.html` and `client/app.ts`:

- `<form id="create-load-form">` must wrap the passphrase field and the confirm button. The confirm button
  `#creation-confirm-saved` stays a real `type="submit"` and is never given `disabled`, `aria-disabled`,
  `aria-busy` or `readonly`. `#publish-create` stays `type="button"` (it is disabled only while it runs).
- `#master-mnemonic`: a visible `<input type="password" name="password" autocomplete="new-password">`. Never
  hide, shrink, make `readonly`, swap for a `<textarea>`, or pair with a duplicate password field. It must be
  `type="password"` at submit: `setCreationConfirmStep` re-masks it whatever the eye toggle left.
- `#create-username` is `<input type="hidden" name="username">`, set through `setHiddenUsername()`: first with the
  provisional DID, then replaced with the **final** DID (Alias applied) before the confirm step shows. Do not turn
  it into a text input, move it offscreen, or edit `.value` in place.
- Nothing `readonly`, `disabled`, offscreen, tiny or transparent may be inside the form while it can be
  submitted. The unmasked overlay (`#master-mnemonic-display`, a readonly textarea) therefore does not exist in
  the markup: `ensurePassphraseOverlay()` creates it only while the Passphrase is revealed and
  `dropPassphraseOverlay()` removes it before the confirm step.
- The confirm step stays: Create (script) persists, then the user's own click submits. Skipping it
  (`EXPERIMENTAL_SKIP_CREATION_CONFIRM`) removes the submit gesture.
- `showDraftPhrase()` dispatches an `input` event after setting the Passphrase, and the `beforeunload` /
  `pagehide` blanking of `#master-mnemonic` stays: without it a half-finished draft is staged as a login.
- Over http(s) the form is a POST to the page it is on, keeping `location.search` (a pending `/authorize`). A
  `file://` build cannot POST and keeps the native GET. Any host that serves the wallet must answer that POST
  (Caddy: `method @post GET`; `scripts/dev-static-server.ts` already does).
- The `formdata` listener that deletes `password` on both forms (`#create-load-form` and the embedded save form) must
  stay: it keeps the Passphrase out of the request. Do not instead rename or remove the field's `name`: the detector
  uses it.
- Do not add a second form, or any other `type="text"` input, **inside** this page's form "for the manager". The Alias
  input is outside it (`#creation-alias-create-row` is a sibling of the form; `#create-load-form` is
  `display: contents` and the flex order in styles.css keeps the Alias between the Passphrase and Create). Measured
  2026-10-16 with the detector Pass bundles (`@protontech/autofill` 0.0.38040317, random forest): a displayed text
  input inside the form at the confirm step turns it into `noop` and the Passphrase field is no longer detected, so
  nothing is saved. Attributes do not help (`data-protonpass-ignore`, `form="x"`, `type="search"` all left it `noop`);
  `readonly`/`disabled` do, but they are the "busy" markers 9.1 forbids; moving the input out of the form does.

### 9.3 Things that were not the cause

The Bun to esbuild build change (builds from 9/13 and 10/07 failed the same way while the extension was the
problem), and GET versus POST for the final form (both fire). `class` names such as `recovery-field` are not among
the detector's features for a username, and were not touched. Each was suspected and cost time.

### 9.4 The embedded create (biset) saves from a top-level page of the same tab

The frame asks for one thing: a **mail address**. Its field is the typed local part and a fixed, uneditable
"@did.md" in one grey box (`name@did.md`; whatever is typed or pasted is lower-cased, cut at any "@" and reduced
to `a-z 0-9 -`). The input is exactly as wide as its text (monospace, so one `ch` per character; it shrinks and
scrolls when the row is full) and the suffix is joined to it: `x@did.md`, `xx@did.md`, `xxx@did.md`. The DID's host stays `<local>.did.md`, which is what `selectedCreationAliasHost()` builds from the
value. The Passphrase is **not** in the frame: its row is hidden, and the person first sees it on the last page
(below). The password manager's account name is the mail address, not the DID. Until the wallet has looked for an
existing identity the frame is hidden (`data-embed-ready`), so the create form never flashes before the finished
view; on a return the finished view shows the mail address and keeps the form's height, and biset starts the
frame at the height it had last time, so nothing on the embedding page moves. The embedding page shows no status
line on the happy path (only failures): a line appearing or disappearing pushed the form up and down.

An iframe never gets the save prompt (9.1), so `?embed=create` splits the job. The frame has Mail, Passphrase and
Create. Create persists the identity in this origin's IndexedDB (shared with the top-level wallet because
`mail.did.md` and `dito.did.md` are one site), parks `{did, passphrase}` in `sessionStorage` and sends the parent
page a `save-page` event over the port. The parent (biset) navigates **its own tab** to
`dito.did.md/?embed=save&return=<its own URL>`; nothing in the message is a URL, so dito cannot steer biset
anywhere. No new tab or window: nothing for a popup blocker to stop, and no `window.open` after an `await`.

- **"creating ." is plain HTML and CSS, on screen from the first paint.** `public/index.html` decides before the
  wallet script loads: a small inline script sets `data-embed="save"` on `<html>` for `?embed=save` and
  `?embed=save-done` (hiding the wallet's own screen), and a static `#embed-save` holds "creating" whose dots are a
  CSS animation. The wallet script is large; until it started, the home screen showed for a moment (the flicker
  between pages). `app.ts` adopts that panel instead of building one. Keep it that way: do not move this decision
  back into the script, and do not make the panel depend on it.
- **`/?embed=save`** reads the parked values and shows only "creating ." with its dots moving. Underneath is a form
  of exactly the 9.2 shape, built by `app.ts` (`EMBED_SAVE`): a hidden `username` with the **mail address** (`name@did.md`), a password
  input, one submit button. They are kept at full size and full opacity (the detector must count them visible) with
  only their text, background and border transparent (`.embed-save-ghost`). Do not shrink, hide or fade them: a
  1 px or `opacity: 0.01` field was ignored. After `EMBED_SAVE_AUTO_SUBMIT_MS` (1500 ms; a script-made click is
  enough for Proton Pass, confirmed 2026-10-11; 400 ms was too short) the page submits the form itself, so arriving
  is the whole gesture.
  **Bitwarden** (read in `bitwarden/clients`, `apps/browser/src/autofill`, 2026-10-21) differs from Proton Pass in two
  ways that matter here. It never collects `input[type=hidden]` (`ignoredInputTypes`), so the hidden `username` is
  invisible to it and, with no username, `shouldAttemptNotification` rejects both Add and Change: the page therefore
  also carries a visible text `#save-account` (same value) outside the form. And a field counts as visible only if
  `elementFromPoint` at its centre returns the field itself (`DomElementVisibilityService`), so the username, the
  Passphrase input and the button sit in separate 32 px rows, never stacked in one cell (the button used to cover
  the Passphrase input). Only the status text, `pointer-events: none`, is drawn over them.
  **Proton Pass, embedded (2026-10-21, from its extension log and sources):** its log shows one `Stage` per attempt, and
  that is the **frame's** form at the moment Create is pressed, not the save page's. The save prompt then shows the
  username that form holds. The frame's hidden `#create-username` starts as the provisional DID (`...:ex.alias`), so
  that is what got saved. `syncEmbedUsername()` (app.ts) edits its value in place to the mail address on every Alias
  input and in a capture-phase click listener before Proton reads it. Do not replace the element (it stopped Pass
  firing), do not drop it (no username: no prompt), and do not rely on the save page's form for the account name.
- **`/?embed=save-done`** (the POST's landing page) is the **last page** and has three things and nothing else: the
  Passphrase in a copy field, "Saved the passphrase?", and "Yes". Yes clears the parked values and sends the tab
  back to the return URL. Nothing moves on its own, and the page holds no `<form>` and no input (a leftover
  password form reads as a failed submit): the manager's prompt is shown on this page about a second after the
  POST and the person answers it before pressing Yes. A close at 200 ms removed the prompt.
- The return URL is accepted only if its origin is the embedding page's own (`mail.did.md`; `mail.did.localhost`
  in dev); otherwise Yes closes the tab instead of navigating (no open redirect). It is read from the query once,
  at module load, because boot rewrites the URL, and kept in `sessionStorage` for the POST's landing page.
- `sessionStorage` is shared by this origin's documents in this tab and gone with it, which is why the Passphrase
  can cross from the frame to the top-level page without the parent ever seeing it. The values expire after ten
  minutes and are removed on Yes. A page loaded without them shows only the question.
- Find the shortest delay that still fires on a machine without rebuilding: in the wallet origin's console run
  `localStorage.setItem("dito.saveDelayMs", "800")` (remove the key to return to the default), then try Create.
  The delay is the time the manager's detector needs (DOM settle of about 40 ms, an idle callback, then its
  classifier). Keep it as short as it still fires; Create to last page should feel instant.
- Nobody reads the Passphrase on the save page itself; someone without a manager copies it from the last page or
  from the frame's own field (eye and copy buttons), so keep those working.
- Keep the save form's ids distinct from the main form's (`save-username`, `save-passphrase`): `query()` in
  `app.ts` prefers the live document, so a duplicate `#master-mnemonic` would be picked up by the main app.
- It only works when the frame and the wallet are the same site. Cross-site, the frame's storage is partitioned
  and empty (PLAN-embedded-wallet.md), so the embed is not offered there.
- Two entrances, two ways to make the DID (Create handler in `app.ts`). The embed (biset) has a mandatory Alias, so
  the genesis is built at `name.did.md` directly: no `…:ex.alias` DID, no move entry. dito itself has an optional
  Alias, so it keeps the provisional DID (its SCID is on screen before Create) and appends a move entry. The library
  (`didwebvh-ts`) writes the old DID into `alsoKnownAs` on every move, so `Identity.prepareUpdate` drops
  `…:ex.alias` from the next entry on; the move entry itself stays in the log.

### 9.5 The embedded create also signs in (the last page is `/authorize`)

Everything the person sees stays the same; the sign-in rides along in the background. biset starts preparing the
sign-in request the moment Create is pressed (the frame sends `creating` with the host `name.did.md`; biset prepares
a `redirect_uri:` SIOPv2 sign-in (§7.1) with `login_hint` pinned to that host, and saves its pending authorization as for any login).
When the page moves on, biset passes the request's query string to the save page as `login=`.

- The save page accepts it only in the shape a relying party sends (`client_id` of `redirect_uri:…`, or a did:webvh JAR with
  `request`, `response_type`), only on this origin's `/authorize`, and marks the tab (`dito.embed-login`). Its form then POSTs to
  `/authorize?...`; **that page is the last page** (`EMBED_LOGIN`, `app.ts`; `public/index.html` hides the wallet
  from the first paint for it too).
- On the last page, while the password manager's prompt is answered, the wallet runs the ordinary approval with the
  parked Passphrase: `beginOAuthAuthorization` (the request parsed as §7.1; a JAR's signature checked against the relying party's own DID), `unlockIdentity`, `approveAuthorization` (the DID document edit is
  published, the capability VC and `id_token` signed). Only the delivery is held (`embedLoginDeliver`): "Yes" hands
  the prepared response to the relying party (`/wallet/callback#vp_token=...`), and biset finishes as for any login.
  Yes before it is ready shows "creating ." until it is. A failure shows a short line and Yes returns to `return`.
- The consent is the Create click made in this wallet's own frame, and the approval is limited to the page that
  opened the tab: the request's redirect origin must equal the return URL's origin (`embedSignInTargetsPage`;
  on a developer machine `mail.did.localhost` stands in for `https://mail.did.md`).
- **Deployment prerequisites (not code):** the relying-party identity is per origin. For `mail.did.md` biset needs
  its own RP DID whose document lists `https://mail.did.md/wallet/callback` as a `SIOPRedirectTarget` service; biset names the DID
  in its config (`rpDid`, sent as `client_metadata.rp_did`). There is no signer. Caddy for `dito.did.md` must also answer a POST to
  `/authorize` (`method @post GET`, as for the app) and `mail.did.md` must serve `/wallet/callback`.
- Checked locally with a test RP DID (`scripts/create-rp-did.ts`), biset's real rp-signer, and a stand-in for the
  did.md host: Create, the last page, the DID document edit (`#didcomm`, the device key, `#didcomm-rotation`)
  published, "Yes" delivering a signed capability to the callback, and biset reaching its account screen. Not
  checked here: the live mediator registration and the live did.md host.

### 9.6 When it stops firing: five minutes

1. `node scripts/pm-probe.ts`, open `http://localhost:8794/signup`, type an email and a password, submit. If no
   dialog appears here, the extension, its settings or the browser profile is the problem (update, reinstall, try
   another profile); do not touch dito. This is what happened on 2026-10-11, and it looked like a dito regression
   for hours.
2. If `/signup` fires, load the wallet and run Create then the confirm button. List what is inside
   `#create-load-form` in the console: it should be the hidden username, `#master-mnemonic` (type password) and
   `#creation-alias`, nothing else.
3. Still silent: bisect by removing elements one at a time (a script that deletes them after load is enough), and
   try the combinations: the detector's result depended on the pair, not on a single element.
4. Read the detector, not guesses: `@protontech/autofill` (`constants/selectors.js`, `constants/heuristics.js`,
   `utils/exclusion.js`, `features/v1/field.username*.js`) and `applications/pass-extension/src/app/content/services/form/form.tracker.ts`.


### 9.7 How Proton Pass decides (read from its source, 2026-10-22)

Files in `ProtonMail/WebClients`, `applications/pass-extension/src`: `app/content/services/form/form.tracker.ts`
(`processForm`, `onFormSubmit`, `detach`), `app/content/services/autosave/autosave.service.ts` (`reconciliate`),
`autosave.relay.ts` (the sub-frame version), `app/worker/services/form.tracker.ts` (`stage`, `commit`, `stash`,
`onTabLoaded`, the XHR tracker), `lib/utils/form-entry.ts` (`validateFormCredentials`). Only three lines reach the
exported log: `Stage`, `Commit`, `Stash`. **A `Stage` with neither a `Commit` nor a `Stash` after it is a silent
branch**, not a missing log.

- **Stage** (`FORM_TRACKER[submit=true]`): the form's `submit` event or a click on a submit button inside it. Both set
  `interactionAt` themselves, so a scripted `button.click()` stages too (but a scripted submit is the weakest signal:
  the old confirm step, a real click, is the one that has always worked). It needs a tracked form that can autosave
  and, for login/register forms, a non-empty password or username (partial).
- **Commit** happens in `autosave.service.ts#reconciliate`, in the **main frame only**: `autosave.relay.ts` makes
  `reconciliate` a no-op in every sub-frame ("full reconciliation requires cross-frame clustering"). It runs when
  the main frame's detector has nothing to predict on a page (`detectionCount === 0`) or garbage-collects forms.
  `shouldCommit = STAGING && domainmatch && !submissionTypeMatch && valid`:
  - `domainmatch`: this page's URL equals the staged entry's domain, protocol and port.
  - `!submissionTypeMatch`: **no tracked form of the same type is on the page** (a visible one; a login/register form
    still present means "failed login": stash `FORM_TYPE_PRESENT`, logged). So the page after the submit must hold
    no password form the detector counts.
  - `valid`: `submittedAt` is set and the entry holds a non-empty password (non-partial). `submittedAt` is cleared if
    a tracked XHR fails: any `fetch`/XHR **with a body** started within 500 ms of the Stage (or while one is
    loading) whose response is 4xx/5xx marks the submission failed (`onFailed`), with no log line.
  - While a form on the page is `processing` (the 1 s after a submit) `reconciliate` returns without doing anything.
- Entries live per tab. A top-level navigation to another domain stashes `DOMAIN_SWITCH`; closing the tab
  `TAB_DELETED`; a request for an entry that does not match the page, `REQUEST`. **`Stash {TAB_DELETED}` after a
  `Stage` means the entry was still staged when the tab closed: nothing committed it.**
- A sub-frame can stage (it did, for the embedded create) but only the main frame of a later page can commit it.
  So an iframe flow depends on the next top-level page having no password form at the moment of its first
  detection. Everything about the save pages follows from that.

What each manager reads, for the same page: Proton Pass uses the form (hidden `username`, the password, the submit);
Bitwarden ignores hidden inputs and wants a visible username (hence `#save-account`, outside the form). On direct
dito (no iframe) the old flow fired for Proton Pass and not for Bitwarden for exactly this reason.

**The rule we ended up with (the landing, 2026-10-22):** the save is the person's own click on a real submit button of
a real form (visible-size, transparent password field; hidden `username`; a visible username outside the form for
Bitwarden), and the page it navigates to has no password form. No scripted submit, no create draft on the save pages
(`maybeBeginCreateDraft` returns on `EMBED_SAVE`/`EMBED_LOGIN`: the draft was a hidden second Passphrase form), and no
request with a body that can fail in the first 500 ms. For a diagnosis, `localStorage.setItem("dito.debugForms", "1")` in
this origin lists every form and input the page holds (create click, save pages) in the console as one JSON line.

## ID ホストの上限と v2 admin（2026-10-22）

ID を誰でも作れる入口（`PUT {name}.did.md/.well-known/did.jsonl`）には、上限がなかった。いまは次を持つ（`server/host/limits.ts`）。値は **v2 admin から、再起動なしで**変えられる（`admin.manifest.json` が項目を v2 admin に伝え、`v2-admin-settings.ts` が管理側のスナップショットを読む。管理側が止まっても、最後の値か既定値で動く）。

| 項目 | 既定 | 働き |
|---|---|---|
| `limits.createPerHour` | 60 | 新しい ID を 1 時間に受ける数（全体）。0 で作成を止める |
| `limits.maxIdentities` | 20,000 | これだけ持ったら新しい ID は 503 |
| `limits.maxLogBytes` | 256 KiB | did.jsonl の大きさ（以前は 16 MiB） |
| `limits.maxWitnessBytes`、`limits.maxJsonBytes` | 256 KiB、64 KiB | witness、routing など |
| `limits.maxConcurrentValidations` | 4 | 同時に署名を検証するログの数。超えたら待たせず 503 |
| `names.reserved` | なし | 組み込みの予約名（`reserved-names.ts`）に足す名前 |

- 新しい ID の上限と総数は、署名の検証の**前**（安い段階）で見る。
- **停止**: `stop-identity` は、ID の文書（did.jsonl、did.json、atproto-did、routing）を 404 にし、書き込みを 403 にする。何も消さない。`release-identity` で戻す。停止の印は `disabled.json`。
- v2 admin 用の口（`/admin/metrics`、`/admin/actions/*`）は、この処理の自分のポート（127.0.0.1:8787）にあり、Caddy は `/admin/*` を通さない。`/etc/v2-admin/tokens/dito` の Bearer トークンがなければ 404（トークンのファイルがなければ、口そのものがない）。
- IP ごとの作成の上限は未実装（Caddy が Cloudflare の IP を信用する設定と一緒に入れる）。
