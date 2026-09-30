export type BridgeSession = {
  // nonce is RECOMMENDED but only REQUIRED for the implicit/hybrid flows
  // (OIDC Core 3.1.2.1) -- an authorization-code request may omit it,
  // so it must stay optional here.
  clientId: string; redirectUri: string; state: string; nonce?: string;
  pkceChallenge: string; verifiedClaims?: Record<string, unknown>;
  // bridgePkceVerifier: the DCR/code path's own PKCE, proving this bridge
  // (not an interceptor) redeems dito's code -- see DitoClient.exchange.
  // ditoNonce: the PLAN8 direct_post path's replacement for that proof --
  // there is no code to redeem, so a nonce embedded in and echoed back by
  // dito's id_token is what ties the response to this request instead
  // (see DitoClient.verifyDirectPost). Exactly one of the two is set,
  // matching which path issued this session (see /authorize below).
  bridgePkceVerifier?: string; ditoNonce?: string;
};

export class SessionStore<T> {
  private values = new Map<string, { value: T; expiresAt: number }>();
  constructor(private ttlMs = 5 * 60_000) {}
  create(value: T): string { const id = crypto.randomUUID(); this.values.set(id, { value, expiresAt: Date.now() + this.ttlMs }); return id; }
  get(id: string): T | undefined { const item = this.values.get(id); if (!item) return; if (item.expiresAt <= Date.now()) { this.values.delete(id); return; } return item.value; }
  take(id: string): T | undefined { const value = this.get(id); this.values.delete(id); return value; }
  set(id: string, value: T) { if (!this.get(id)) throw new Error("session expired"); this.values.set(id, { value, expiresAt: Date.now() + this.ttlMs }); }
}
