import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { startTestServer, stopTestServer, apiRequest, createUserWithToken, cleanupUsers, runSuffix } from "./testServer.js";
import { prisma } from "../src/lib/prisma.js";
import { signRefreshToken, generateRefreshTokenId } from "../src/lib/jwt.js";

// Regression coverage for the bug where /auth/session/refresh reset
// lastVerifiedAt to now() on every call -- including the automatic,
// no-user-interaction background pings the client fires every few minutes.
// That meant the very next automatic ping after a genuine outage always saw
// a tiny gap and snapped trust straight back to 100, so a session's trust
// could never meaningfully reflect a real period of unreachability as long
// as the device stayed connected afterward.
describe("session trust decay and recovery", () => {
  const emailFor = (n: number) => `trust-decay-${n}-${runSuffix}@example.com`;
  const allEmails = Array.from({ length: 10 }, (_, i) => emailFor(i));

  beforeAll(async () => {
    await startTestServer();
    await cleanupUsers(allEmails);
  });

  afterAll(async () => {
    await cleanupUsers(allEmails);
    await stopTestServer();
  });

  let caseCounter = 0;

  async function makeBackdatedSession(hoursAgo: number, trustLevel = 100) {
    const { user } = await createUserWithToken({ email: emailFor(caseCounter++), role: "MEMBER" });
    // P0-4: a refresh token only rotates (succeeds) if its jti matches
    // Session.currentRefreshTokenId, so the session must be created with the
    // exact jti the signed token below carries -- otherwise every call here
    // would be indistinguishable from replay against a token-less legacy
    // session and would 401 + delete the session instead of exercising the
    // trust-decay math this file is actually about.
    const refreshTokenId = generateRefreshTokenId();
    const session = await prisma.session.create({
      data: {
        userId: user.id,
        deviceId: "test-device",
        trustLevel,
        lastVerifiedAt: new Date(Date.now() - hoursAgo * 3_600_000),
        expiresAt: new Date(Date.now() + 30 * 24 * 3_600_000),
        currentRefreshTokenId: refreshTokenId,
      },
    });
    const refreshToken = signRefreshToken({ sub: user.id, sessionId: session.id }, refreshTokenId);
    return { user, session, refreshToken };
  }

  it("stays at full trust across continuous, closely-spaced check-ins", async () => {
    const { refreshToken } = await makeBackdatedSession(4 / 60); // last verified 4 minutes ago
    const res = await apiRequest("/auth/session/refresh", { method: "POST", refreshToken });
    expect(res.status).toBe(200);
    expect(res.data.trustLevel).toBe(100);
  });

  it("reports decayed trust after a real multi-hour gap, not full trust", async () => {
    const { refreshToken } = await makeBackdatedSession(5); // unreachable for 5 hours
    const res = await apiRequest("/auth/session/refresh", { method: "POST", refreshToken });
    expect(res.status).toBe(200);
    // 5 hours * 5 points/hour = 25 points of decay -> ~75, plus one check-in's
    // worth of recovery (+5) -> ~80. Should be well below 100, not snapped back.
    expect(res.data.trustLevel).toBeLessThan(90);
    expect(res.data.trustLevel).toBeGreaterThan(60);
  });

  it("recovers gradually across repeated check-ins rather than jumping straight to 100", async () => {
    const { session, refreshToken } = await makeBackdatedSession(5);

    const first = await apiRequest("/auth/session/refresh", { method: "POST", refreshToken });
    const firstTrust = first.data.trustLevel as number;
    expect(firstTrust).toBeLessThan(100);

    // Immediately re-sign a fresh refresh token against the now-updated
    // session (its lastVerifiedAt just advanced to "now") and call again --
    // this simulates the very next automatic background ping a few minutes
    // later. Before the fix, this alone would jump trust straight to 100.
    //
    // P0-4: the first call above already rotated Session.currentRefreshTokenId
    // to a new jti, so this second token must be signed carrying *that* jti
    // (read fresh from the row, exactly as a real client would receive it
    // via its rotated Set-Cookie) -- signing a token for the original,
    // now-rotated-away jti here would correctly be treated as reuse, not as
    // "the next legitimate check-in" this test is actually exercising.
    const refreshedSession = await prisma.session.findUniqueOrThrow({ where: { id: session.id } });
    expect(refreshedSession.trustLevel).toBe(firstTrust);
    expect(Number.isInteger(firstTrust)).toBe(true);

    const secondToken = signRefreshToken(
      { sub: session.userId, sessionId: session.id },
      refreshedSession.currentRefreshTokenId!,
    );
    const second = await apiRequest("/auth/session/refresh", { method: "POST", refreshToken: secondToken });
    const secondTrust = second.data.trustLevel as number;

    // Should have recovered *some* but still not be back to full trust from
    // one more immediate check-in.
    expect(secondTrust).toBeGreaterThan(firstTrust);
    expect(secondTrust).toBeLessThan(100);
  });
});
