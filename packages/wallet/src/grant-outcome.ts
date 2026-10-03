/**
 * Outcome reporting for OAuth grants (pure logic, no DOM / IndexedDB).
 *
 * A relying party that registered `outcome_reporting: true` tells the authorization server
 * whether its sign-in finished (`active`) or failed (`failed`); the wallet polls
 * GET /v1/oauth/outcome/<capabilityId> and keeps the answer on the stored grant. A grant with
 * no `outcome` predates this or belongs to a non-reporting RP and is simply "active", as before.
 */

export type GrantOutcome = "pending" | "active" | "failed";
export type GrantDisplayState = "active" | "pending" | "failed" | "unconfirmed";

/** What the server reports (200 body of the outcome endpoint). A 404 is passed as `null`. */
export type ServerOutcome = { status: "active" | "failed"; reason?: string; updatedAt?: string };

/** The fields of a stored grant this module reads or writes. */
export type OutcomeGrant = {
  issuedAt: string;
  outcome?: GrantOutcome;
  outcomeReason?: string;
  outcomeCheckedAt?: string;
};

/** A pending sign-in older than this is shown as unconfirmed. */
export const OUTCOME_CONFIRM_MS = 10 * 60 * 1000;
/** A late report still updates the card for this long after approval. */
export const OUTCOME_POLL_WINDOW_MS = 24 * 60 * 60 * 1000;
export const OUTCOME_REASON_MAX = 200;

function ageMs(grant: OutcomeGrant, now: Date): number {
  return now.getTime() - Date.parse(grant.issuedAt);
}

export function grantDisplayState(grant: OutcomeGrant, now: Date): GrantDisplayState {
  if (grant.outcome === undefined || grant.outcome === "active") return "active";
  if (grant.outcome === "failed") return "failed";
  return ageMs(grant, now) > OUTCOME_CONFIRM_MS ? "unconfirmed" : "pending";
}

export function applyOutcome<T extends OutcomeGrant>(grant: T, server: ServerOutcome | null, now: Date): T {
  const checked = { ...grant, outcomeCheckedAt: now.toISOString() };
  // A grant without `outcome` is not reporting; never start tracking it. `active` is final.
  if (!server || grant.outcome === undefined || grant.outcome === "active") return checked;
  if (server.status === "active") {
    const { outcomeReason: _drop, ...rest } = checked;
    return { ...rest, outcome: "active" } as T;
  }
  if (server.status === "failed") {
    const reason = typeof server.reason === "string" ? server.reason.trim().slice(0, OUTCOME_REASON_MAX).trim() : "";
    const { outcomeReason: _drop, ...rest } = checked;
    return { ...rest, outcome: "failed", ...(reason ? { outcomeReason: reason } : {}) } as T;
  }
  return checked;
}

/** Poll grants still waiting for (or missing) a report, for up to 24h after approval. A grant
 * confirmed `failed` or `active`, and one that does not report at all, is not polled. */
export function shouldPoll(grant: OutcomeGrant, now: Date): boolean {
  if (grant.outcome !== "pending") return false;
  const age = ageMs(grant, now);
  return Number.isFinite(age) && age <= OUTCOME_POLL_WINDOW_MS;
}
