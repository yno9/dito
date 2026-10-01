import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { verifyIdTokenSignature } from "../../../packages/did-verify/index.ts";
import { createSelfIssuedIdToken } from "../../../packages/wallet/src/did-webvh.ts";

export type DitoRegistration = { client_id: string; registration_access_token?: string };
type RpDidKey = { did: string; verificationMethod: string; privateKey: string };

function atomicWrite(path: string, value: string) {
  mkdirSync(dirname(path), { recursive: true }); const temporary = `${path}.${process.pid}.tmp`;
  writeFileSync(temporary, value, { mode: 0o600 }); renameSync(temporary, path);
}
export function randomBase64url(bytes = 32) { return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url"); }
export async function pkceChallenge(verifier: string) { return Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url"); }

export class DitoClient {
  registration?: DitoRegistration;
  private rpDidKey?: RpDidKey;
  // PLAN6: rpDidKeyFile, when set, switches this client from the DCR
  // client_id/secret model to a JAR (RFC 9101) Authorization Request
  // signed by this RP's own did:webvh key (see
  // PLAN6-rp-did-authentication §0.5, §0.1). oidc-bridge holds
  // a real backend process and its own secret storage (DATA_DIR, same as
  // dito-registration.json today), so -- unlike biset's serverless
  // `https://t.biset.md` frontend, which needs a dedicated signing service
  // (biset-rp-signer) -- it can just sign inline, synchronously, here.
  constructor(readonly issuer: string, readonly redirectUri: string, readonly registrationFile: string, readonly authorizationEndpoint = `${issuer}/v1/oauth/authorize`, readonly walletIdentityDomain = "did.md", private readonly rpDidKeyFile?: string, readonly responseUri?: string) {}
  get isRpDid(): boolean { return !!this.rpDidKey; }
  async initialize() {
    if (this.rpDidKeyFile) {
      const key = JSON.parse(readFileSync(this.rpDidKeyFile, "utf8")) as RpDidKey;
      if (!key.did?.startsWith("did:webvh:") || !key.verificationMethod?.startsWith(`${key.did}#`) || typeof key.privateKey !== "string") throw new Error(`${this.rpDidKeyFile} does not contain a valid RP DID key`);
      this.rpDidKey = key;
      this.registration = { client_id: key.did };
      return this.registration;
    }
    try { this.registration = JSON.parse(readFileSync(this.registrationFile, "utf8")); }
    catch {
      const response = await fetch(`${this.issuer}/v1/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ application_type: "web", client_name: "did.md OIDC bridge", redirect_uris: [this.redirectUri], grant_types: ["authorization_code"], response_types: ["code"], scope: "openid profile email", token_endpoint_auth_method: "none" }) });
      if (!response.ok) throw new Error(`dito registration failed: ${response.status} ${await response.text()}`);
      this.registration = await response.json() as DitoRegistration; atomicWrite(this.registrationFile, `${JSON.stringify(this.registration, null, 2)}\n`);
    }
    if (!this.registration?.client_id) throw new Error("invalid dito registration"); return this.registration;
  }
  // Both the DCR path (unset rpDidKey) AND the pre-PLAN8 RP-DID/JAR+code
  // path (rpDidKey set, this.responseUri NOT set -- see server.ts's own
  // comment on why direct_post requires an explicit opt-in, not merely
  // RP_DID_KEY_FILE's presence). Kept working exactly as PLAN6 left it:
  // production already runs with RP_DID_KEY_FILE set today, and its RP DID
  // document does not yet publish the direct_post response_uri (a separate
  // provisioning step -- PLAN8's own checklist) -- deploying this class
  // must not silently break every live login until that catches up.
  async authorizationUrl(state: string, verifier: string) {
    if (!this.registration) throw new Error("dito client is not initialized");
    const challenge = await pkceChallenge(verifier);
    if (this.rpDidKey) {
      const jwt = createSelfIssuedIdToken({
        iss: this.rpDidKey.did, client_id: this.rpDidKey.did, client_id_scheme: "did", response_type: "code",
        redirect_uri: this.redirectUri, state, code_challenge: challenge, code_challenge_method: "S256",
        scope: "openid profile email",
        dcql_query: { credentials: [{ id: "capability", format: "vc+di", meta: { type_values: [["VerifiableCredential", "did.md/DeviceCapability"]] } }] },
      }, { privateKey: new Uint8Array(Buffer.from(this.rpDidKey.privateKey, "base64url")), did: this.rpDidKey.did });
      const url = new URL(this.authorizationEndpoint); url.search = new URLSearchParams({ client_id: this.rpDidKey.did, response_type: "code", request: jwt }).toString();
      return url.toString();
    }
    const url = new URL(this.authorizationEndpoint); url.search = new URLSearchParams({ client_id: this.registration.client_id, redirect_uri: this.redirectUri, response_type: "code", scope: "openid profile email", state, code_challenge: challenge, code_challenge_method: "S256" }).toString();
    return url.toString();
  }
  // PLAN8: oidc-bridge is a
  // real backend (unlike biset's browser-only frontend), so unlike PLAN7's
  // fragment/postMessage delivery for biset, it can receive dito's
  // response via a same-process POST to its own response_uri -- OID4VP's
  // direct_post response mode. This fully replaces the former
  // code+token round trip against api.did.md (this class's own exchange()
  // above, still used when this.responseUri is unset) for the RP-DID path:
  // there is no `code` to protect, so no PKCE either. Only reachable once
  // this.responseUri is set -- see server.ts's explicit-opt-in comment.
  // app: the downstream application (Forgejo, ...) as this bridge asserts it: its display name and
  // its home (`client_uri`, RFC 7591), carried as OID4VP `client_metadata` inside the signed request.
  // The wallet can verify the request really came from this bridge's DID, not that the app is who
  // the bridge says -- it shows the two apart (name, domain, and "via" the bridge).
  directPostAuthorizationUrl(state: string, nonce: string, app?: { name?: string; uri?: string }): string {
    if (!this.rpDidKey) throw new Error("direct_post authorization requires an RP DID key");
    if (!this.responseUri) throw new Error("direct_post authorization requires a response_uri");
    const jwt = createSelfIssuedIdToken({
      iss: this.rpDidKey.did, client_id: this.rpDidKey.did, client_id_scheme: "did", response_type: "vp_token id_token",
      response_mode: "direct_post", response_uri: this.responseUri, state, nonce,
      // scope is independent of dcql_query's capability type (that names
      // the capability document; scope gates id_token issuance -- see
      // client/app.ts's approveAuthorization).
      scope: "openid profile email",
      ...(app && (app.name || app.uri) ? { client_metadata: { ...(app.name ? { client_name: app.name } : {}), ...(app.uri ? { client_uri: app.uri } : {}) } } : {}),
      dcql_query: { credentials: [{ id: "capability", format: "vc+di", meta: { type_values: [["VerifiableCredential", "did.md/DeviceCapability"]] } }] },
    }, { privateKey: new Uint8Array(Buffer.from(this.rpDidKey.privateKey, "base64url")), did: this.rpDidKey.did });
    const url = new URL(this.authorizationEndpoint); url.search = new URLSearchParams({ client_id: this.rpDidKey.did, response_type: "vp_token id_token", request: jwt }).toString();
    return url.toString();
  }
  async exchange(code: string, verifier: string) {
    if (!this.registration) throw new Error("dito client is not initialized");
    const body = new URLSearchParams({ grant_type: "authorization_code", client_id: this.registration.client_id, redirect_uri: this.redirectUri, code, code_verifier: verifier });
    const response = await fetch(`${this.issuer}/v1/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body });
    if (!response.ok) throw new Error(`dito token exchange failed: ${response.status} ${await response.text()}`);
    const tokens = await response.json() as { id_token?: string };
    if (!tokens.id_token) throw new Error("dito did not return an id_token");
    const signer = await verifyIdTokenSignature(tokens.id_token, this.walletIdentityDomain); const claims = JSON.parse(Buffer.from(tokens.id_token.split(".")[1]!, "base64url").toString()) as Record<string, unknown>;
    if (claims.aud !== this.registration.client_id) throw new Error("dito id_token audience mismatch");
    return { claims: { ...claims, sub: signer.sub }, signer, idToken: tokens.id_token };
  }
  // PLAN8: verifies an id_token delivered directly via direct_post -- no
  // token-endpoint round trip. Mirrors exchange()'s checks (signature,
  // audience) plus a nonce check that only matters here: exchange()'s
  // code+PKCE already proved possession of the authorization; direct_post's
  // nonce is what proves this response answers THIS request rather than a
  // replayed one.
  async verifyDirectPost(idToken: string, expectedNonce: string) {
    if (!this.rpDidKey) throw new Error("direct_post verification requires an RP DID key");
    const signer = await verifyIdTokenSignature(idToken, this.walletIdentityDomain);
    const claims = JSON.parse(Buffer.from(idToken.split(".")[1]!, "base64url").toString()) as Record<string, unknown>;
    if (claims.aud !== this.rpDidKey.did) throw new Error("dito id_token audience mismatch");
    if (claims.nonce !== expectedNonce) throw new Error("dito id_token nonce mismatch");
    return { claims: { ...claims, sub: signer.sub }, signer, idToken };
  }
}
