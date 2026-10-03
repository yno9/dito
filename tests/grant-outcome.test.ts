import { expect, test } from "bun:test";
import { applyOutcome, grantDisplayState, shouldPoll } from "../packages/wallet/src/grant-outcome.ts";

const issuedAt = "2026-10-01T00:00:00.000Z";
const at = (ms: number) => new Date(Date.parse(issuedAt) + ms);
const MIN = 60_000;
const HOUR = 60 * MIN;
const base = { issuedAt };

test("display state: legacy grants are active", () => {
  expect(grantDisplayState(base, at(99 * HOUR))).toBe("active");
  expect(grantDisplayState({ ...base, outcome: "active" }, at(99 * HOUR))).toBe("active");
  expect(grantDisplayState({ ...base, outcome: "failed" }, at(0))).toBe("failed");
});

test("display state: pending becomes unconfirmed after 10 minutes", () => {
  const grant = { ...base, outcome: "pending" as const };
  expect(grantDisplayState(grant, at(0))).toBe("pending");
  expect(grantDisplayState(grant, at(10 * MIN))).toBe("pending");
  expect(grantDisplayState(grant, at(10 * MIN + 1))).toBe("unconfirmed");
});

test("applyOutcome: active clears the reason, failed trims and caps it", () => {
  const now = at(MIN);
  const failed = applyOutcome({ ...base, outcome: "pending" }, { status: "failed", reason: `  ${"x".repeat(300)}  ` }, now);
  expect(failed.outcome).toBe("failed");
  expect(failed.outcomeReason).toBe("x".repeat(200));
  expect(failed.outcomeCheckedAt).toBe(now.toISOString());
  const recovered = applyOutcome(failed, { status: "active" }, now);
  expect(recovered.outcome).toBe("active");
  expect("outcomeReason" in recovered).toBe(false);
  expect(applyOutcome({ ...base, outcome: "pending" }, { status: "failed" }, now).outcomeReason).toBeUndefined();
});

test("applyOutcome: 404 only stamps the check time; active never downgrades; input is not mutated", () => {
  const now = at(MIN);
  const pending = { ...base, outcome: "pending" as const };
  expect(applyOutcome(pending, null, now)).toEqual({ ...pending, outcomeCheckedAt: now.toISOString() });
  expect(pending).toEqual({ ...base, outcome: "pending" });
  const active = { ...base, outcome: "active" as const };
  expect(applyOutcome(active, { status: "failed", reason: "no" }, now).outcome).toBe("active");
  expect(applyOutcome({ ...base }, { status: "failed", reason: "no" }, now).outcome).toBeUndefined();
});

test("shouldPoll: pending grants for 24h; never active, failed or legacy", () => {
  const pending = { ...base, outcome: "pending" as const };
  expect(shouldPoll(pending, at(0))).toBe(true);
  expect(shouldPoll(pending, at(30 * MIN))).toBe(true);
  expect(shouldPoll(pending, at(24 * HOUR))).toBe(true);
  expect(shouldPoll(pending, at(24 * HOUR + 1))).toBe(false);
  expect(shouldPoll({ ...base, outcome: "active" }, at(0))).toBe(false);
  expect(shouldPoll({ ...base, outcome: "failed" }, at(0))).toBe(false);
  expect(shouldPoll(base, at(0))).toBe(false);
});
