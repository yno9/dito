# did.md OIDC bridge

This process is an OIDC public client of dito and an RS256 OpenID Provider
for any number of relying parties (Forgejo, Outline, Hi.Events, ...). It
deliberately keeps the stable server key out of dito.

## Clients

Copy `config/clients.example.json` somewhere outside the repository,
replace the placeholder secrets, and keep the file readable only by the
service account. The file holds either a single client object or
a JSON array of them — one entry per relying party, each with its own
`client_id` / `client_secret` / `redirect_uris`.

Example entries (see `config/clients.example.json`):

| client_id | redirect_uri |
|-----------|----------------|
| forgejo | `https://forgejo.example.com/user/oauth2/dito/callback` |
| outline | `https://wiki.example.com/auth/oidc.callback` |
| hievents | `https://form.example.com/api/auth/did/callback` |

Configure each relying party with
`https://oidc-bridge.did.md/.well-known/openid-configuration`.

**Client config is re-read from disk about every 15s**, so adding a new RP
does not require restarting the bridge (sessions/codes already in flight
still authenticate against the map that was live when they were created).

## Keys and sessions

The service stores its RSA private key and dito dynamic registration below
`DATA_DIR` (`./data/oidc-bridge` by default); both survive
restarts and must be backed up. The private key is created with mode `0600`.
Login sessions, authorization codes, and access tokens are held in memory
with five-minute, two-minute, and five-minute lifetimes respectively. A
multi-process deployment needs a shared single-use store such as Redis
before scaling out.

## Endpoints

- `/authorize` — requires `response_type=code`, `state`, and S256 PKCE
- `/callback` — dito → bridge
- `/token` — client_secret_basic or client_secret_post + PKCE verifier
- `/jwks` — RS256 public key
- `/userinfo` — Bearer access token; returns the OIDC-standard claim subset
- `/healthz` — liveness

## Environment

| Variable | Default | Notes |
|----------|---------|-------|
| `BRIDGE_ISSUER` | `https://oidc-bridge.did.md` | public issuer |
| `DITO_ISSUER` / `DISPO_ISSUER` | `https://api.did.md` | upstream API |
| `DITO_AUTHORIZATION_ENDPOINT` / `DISPO_AUTHORIZATION_ENDPOINT` | `https://app.did.md/authorize` | browser IdP |
| `CLIENTS_CONFIG` | `server/oauth/config/forgejo-client.json` | keep real client secrets outside the repository |
| `FORGEJO_CLIENT_CONFIG` | — | legacy alias for `CLIENTS_CONFIG` |
| `DATA_DIR`, `HOST`, `PORT` | `./data/oidc-bridge`, `127.0.0.1`, `8790` | |

## Run

```sh
bun run start:bridge          # local
bun test server/oauth/tests   # flow tests
bun build --compile --target=bun-linux-x64 --outfile did-md-oidc-bridge server/oauth/src/server.ts
```

Put it behind a TLS-terminating reverse proxy on its issuer host (default port 8790).
