import { describe, it, expect } from "vitest";
import { authenticator } from "otplib";
import { checkTotpWithTolerance } from "../src/lib/totp.js";

// otplib's default options (never overridden anywhere in this codebase) give
// zero clock-drift tolerance: a code is only valid for the exact current
// 30-second step. checkTotpWithTolerance replaces that with a tight +/-5s
// window instead of the coarser whole-step "window" option otplib exposes
// (which only comes in 30s increments). These tests pin a fixed reference
// instant 3 seconds into a real 30-second step so the boundary-crossing
// scenarios are deterministic rather than depending on when the test happens
// to run relative to a real step boundary.
const STEP_MS = 30_000;

function pinnedInstant() {
  const boundary = Math.floor(Date.now() / STEP_MS) * STEP_MS;
  return boundary + 3_000; // 3s into the current step
}

describe("TOTP clock-drift tolerance", () => {
  it("accepts a code with no drift at all", () => {
    const secret = authenticator.generateSecret();
    const code = authenticator.generate(secret);
    expect(checkTotpWithTolerance(code, secret)).toBe(true);
  });

  it("accepts a code from a client clock 4s behind, even across a real step boundary", () => {
    const secret = authenticator.generateSecret();
    const serverNow = pinnedInstant();
    const clientEpoch = serverNow - 4_000; // lands in the previous 30s step

    const clientCode = authenticator.clone({ epoch: clientEpoch }).generate(secret);

    // Sanity check: prove this genuinely is a different step, so an exact
    // (zero-tolerance) check would have rejected it -- otherwise this test
    // wouldn't actually be exercising the tolerance window at all.
    expect(authenticator.clone({ epoch: serverNow }).check(clientCode, secret)).toBe(false);

    expect(checkTotpWithTolerance(clientCode, secret, 5_000, serverNow)).toBe(true);
  });

  it("accepts a code from a client clock 4s ahead, even across a real step boundary", () => {
    const secret = authenticator.generateSecret();
    const serverNow = pinnedInstant();
    const clientEpoch = serverNow + 4_000;

    const clientCode = authenticator.clone({ epoch: clientEpoch }).generate(secret);
    expect(checkTotpWithTolerance(clientCode, secret, 5_000, serverNow)).toBe(true);
  });

  // A drift greater than step + tolerance (30s + 5s = 35s here) can never
  // share a 30-second bucket with the +/-5s window no matter where "now"
  // falls relative to a step boundary -- see the comment in src/lib/totp.ts
  // for why anything closer to the boundary than that can't be guaranteed
  // rejected (bucket granularity is coarser than the tolerance).
  it("rejects a code from a client clock 40s off -- unambiguously outside any possible overlap", () => {
    const secret = authenticator.generateSecret();
    const serverNow = pinnedInstant();
    const clientEpoch = serverNow - 40_000;

    const clientCode = authenticator.clone({ epoch: clientEpoch }).generate(secret);
    expect(checkTotpWithTolerance(clientCode, secret, 5_000, serverNow)).toBe(false);
  });

  it("rejects a code generated with the wrong secret entirely", () => {
    const secret = authenticator.generateSecret();
    const otherSecret = authenticator.generateSecret();
    const code = authenticator.generate(otherSecret);
    expect(checkTotpWithTolerance(code, secret)).toBe(false);
  });
});
