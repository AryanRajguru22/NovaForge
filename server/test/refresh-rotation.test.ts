import { describe, it, expect, beforeAll, afterAll } from "vitest";
import jwt from "jsonwebtoken";
import { startTestServer, stopTestServer, apiRequest, cleanupUsers, runSuffix } from "./testServer.js";
import { prisma } from "../src/lib/prisma.js";
import { signAccessToken, signRefreshToken, generateRefreshTokenId } from "../src/lib/jwt.js";
import { REFRESH_ROTATION_GRACE_MS } from "../src/lib/refreshRotation.js";
import { env } from "../src/lib/env.js";
import type { Role } from "@prisma/client";

// P0-4 regression coverage: server/src/routes/auth.ts's POST
// /session/refresh previously verified a refresh JWT's signature and
// expiry, confirmed its named Session was still live, and unconditionally
// issued a brand-new access/refresh pair -- without ever invalidating the
// token that was just presented. Every refresh token ever issued for a
// session therefore remained simultaneously valid for that session's entire
// (up to 30-day) lifetime: a stolen refresh token was reusable indefinitely,
// and using it never affected the legitimate copy. These tests exercise the
// real fix end-to-end against a real Postgres-backed test server: atomic
// jti rotation (server/src/lib/refreshRotation.ts), a short grace window for
// genuinely concurrent legitimate refreshes, and replay detection that
// revokes the whole session via the exact same deletion mechanism
// requireAuth/Socket.io already treat as authoritative.

function extractSetCookies(res: Response): string[] {
  const getSetCookie = (res.headers as Headers & { getSetCookie?: () => string[] }).getSetCookie;
  return typeof getSetCookie === "function" ? getSetCookie.call(res.headers) : [];
}

function extractCookieValue(setCookies: string[], name: string): string | undefined {
  for (const header of setCookies) {
    const [pair] = header.split(";");
    const eq = pair.indexOf("=");
    if (eq === -1) continue;
    if (pair.slice(0, eq) === name) return pair.slice(eq + 1);
  }
  return undefined;
}

describe("P0-4: refresh token rotation and replay detection", () => {
  const emails: string[] = [];
  let baseUrl = "";

  beforeAll(async () => {
    baseUrl = await startTestServer();
  });

  afterAll(async () => {
    await cleanupUsers(emails);
    await stopTestServer();
  });

  function nextEmail(label: string): string {
    const email = `p04-${label}-${runSuffix}@example.com`;
    emails.push(email);
    return email;
  }

  /** Creates a fresh user + session, matching exactly what a real login
   * produces via issueSession (server/src/routes/auth.ts): a Session row
   * whose currentRefreshTokenId is the same jti the returned refresh JWT
   * carries -- "the token and database state must agree exactly" from the
   * very first moment, as P0-4 requires. */
  async function login(email: string, role: Role = "MEMBER") {
    const user = await prisma.user.create({ data: { email, name: "P0-4 Test User", role } });
    const refreshTokenId = generateRefreshTokenId();
    const session = await prisma.session.create({
      data: {
        userId: user.id,
        deviceId: "test-device",
        expiresAt: new Date(Date.now() + 30 * 24 * 3_600_000),
        currentRefreshTokenId: refreshTokenId,
      },
    });
    const accessToken = signAccessToken({ sub: user.id, sessionId: session.id });
    const refreshToken = signRefreshToken({ sub: user.id, sessionId: session.id }, refreshTokenId);
    return { user, session, accessToken, refreshToken, refreshTokenId };
  }

  /** Raw fetch bypassing apiRequest (server/test/testServer.ts), used only
   * where a test needs the actual Set-Cookie headers -- apiRequest itself
   * only ever surfaces {status, data}. */
  async function rawRefresh(refreshToken: string) {
    const res = await fetch(`${baseUrl}/api/auth/session/refresh`, {
      method: "POST",
      headers: { Cookie: `refreshToken=${refreshToken}` },
    });
    const setCookies = extractSetCookies(res);
    const data = await res.json().catch(() => ({}));
    return { status: res.status, data, setCookies };
  }

  function backdateRotation(sessionId: string, beyondGrace = true) {
    const offset = beyondGrace ? REFRESH_ROTATION_GRACE_MS + 1_000 : 0;
    return prisma.session.update({
      where: { id: sessionId },
      data: { rotatedAt: new Date(Date.now() - offset) },
    });
  }

  it("TEST 1: a normal refresh rotates the token, and the issued cookie's jti matches what's now on record", async () => {
    const { session, refreshToken, refreshTokenId } = await login(nextEmail("1"));

    // Uses rawRefresh (not apiRequest) so the actual issued cookie can be
    // decoded and compared against the database in the same call -- proving
    // the token handed to the client and the database's notion of "current"
    // genuinely agree, not just that some rotation happened.
    const { status, setCookies } = await rawRefresh(refreshToken);
    expect(status).toBe(200);

    const issuedRefreshToken = extractCookieValue(setCookies, "refreshToken");
    expect(issuedRefreshToken).toBeDefined();
    const decoded = jwt.decode(issuedRefreshToken!) as { jti?: string } | null;

    const updated = await prisma.session.findUniqueOrThrow({ where: { id: session.id } });
    expect(updated.currentRefreshTokenId).not.toBe(refreshTokenId);
    expect(updated.currentRefreshTokenId).not.toBeNull();
    expect(updated.previousRefreshTokenId).toBe(refreshTokenId);
    expect(updated.rotatedAt).not.toBeNull();
    expect(decoded?.jti).toBe(updated.currentRefreshTokenId);
  });

  it("TEST 2: the old token is rejected once the grace window has passed, and the session is revoked", async () => {
    const { session, refreshToken, refreshTokenId } = await login(nextEmail("2"));

    const first = await apiRequest("/auth/session/refresh", { method: "POST", refreshToken });
    expect(first.status).toBe(200);

    await backdateRotation(session.id);

    const replay = await apiRequest("/auth/session/refresh", { method: "POST", refreshToken });
    expect(replay.status).toBe(401);

    const deleted = await prisma.session.findUnique({ where: { id: session.id } });
    expect(deleted).toBeNull();
    void refreshTokenId;
  });

  it("TEST 3: replay outside grace revokes the whole session, invalidating its access token too", async () => {
    const { session, accessToken, refreshToken } = await login(nextEmail("3"));

    const meBefore = await apiRequest("/auth/me", { token: accessToken });
    expect(meBefore.status).toBe(200);

    const first = await apiRequest("/auth/session/refresh", { method: "POST", refreshToken });
    expect(first.status).toBe(200);

    await backdateRotation(session.id);

    const replay = await apiRequest("/auth/session/refresh", { method: "POST", refreshToken });
    expect(replay.status).toBe(401);

    const meAfter = await apiRequest("/auth/me", { token: accessToken });
    expect(meAfter.status).toBe(401);
  });

  it("TEST 4: the newly rotated token itself successfully rotates again", async () => {
    const { session, refreshToken } = await login(nextEmail("4"));

    const first = await apiRequest("/auth/session/refresh", { method: "POST", refreshToken });
    expect(first.status).toBe(200);

    const afterFirst = await prisma.session.findUniqueOrThrow({ where: { id: session.id } });
    const newJti = afterFirst.currentRefreshTokenId!;
    const secondToken = signRefreshToken({ sub: session.userId, sessionId: session.id }, newJti);

    const second = await apiRequest("/auth/session/refresh", { method: "POST", refreshToken: secondToken });
    expect(second.status).toBe(200);

    const afterSecond = await prisma.session.findUniqueOrThrow({ where: { id: session.id } });
    expect(afterSecond.previousRefreshTokenId).toBe(newJti);
    expect(afterSecond.currentRefreshTokenId).not.toBe(newJti);
  });

  // The central concurrency property: genuinely parallel (Promise.all, not
  // sequential) requests presenting the SAME current token must never both
  // independently rotate -- exactly one CAS can ever match
  // WHERE currentRefreshTokenId = presentedJti, since the first to commit
  // changes that value out from under the second before it evaluates its
  // own WHERE clause. Run multiple times (see the verification report) to
  // build confidence this isn't timing-lucky.
  it("TEST 5: two genuinely concurrent refreshes with the same token converge on one rotation, never two", async () => {
    const { session, refreshToken, refreshTokenId } = await login(nextEmail("5"));

    const [r1, r2] = await Promise.all([rawRefresh(refreshToken), rawRefresh(refreshToken)]);

    expect(r1.status).toBe(200);
    expect(r2.status).toBe(200);

    const jti1 = jwt.decode(extractCookieValue(r1.setCookies, "refreshToken") ?? "") as { jti?: string } | null;
    const jti2 = jwt.decode(extractCookieValue(r2.setCookies, "refreshToken") ?? "") as { jti?: string } | null;
    expect(jti1?.jti).toBeTruthy();
    expect(jti1?.jti).toBe(jti2?.jti);

    const updated = await prisma.session.findUniqueOrThrow({ where: { id: session.id } });
    // previousRefreshTokenId being the ORIGINAL jti (not some intermediate
    // value) proves exactly one rotation happened -- a second, divergent
    // rotation chained on top of the first would have advanced previous to
    // whatever the first rotation's own new jti was instead.
    expect(updated.previousRefreshTokenId).toBe(refreshTokenId);
    expect(updated.currentRefreshTokenId).toBe(jti1?.jti);

    // The converged current token is genuinely usable, not just recorded.
    const followUp = signRefreshToken({ sub: session.userId, sessionId: session.id }, updated.currentRefreshTokenId!);
    const third = await apiRequest("/auth/session/refresh", { method: "POST", refreshToken: followUp });
    expect(third.status).toBe(200);
  });

  it("TEST 6: the grace window is time-bounded, not a permanent amnesty", async () => {
    const { session, refreshToken } = await login(nextEmail("6"));

    const first = await apiRequest("/auth/session/refresh", { method: "POST", refreshToken });
    expect(first.status).toBe(200);

    // Within grace: presenting the ORIGINAL (now rotated-away) token again
    // must still succeed -- this is the legitimate-concurrent-tab case.
    const withinGrace = await apiRequest("/auth/session/refresh", { method: "POST", refreshToken });
    expect(withinGrace.status).toBe(200);

    // Deterministically push rotatedAt back beyond the grace window instead
    // of sleeping for it.
    await backdateRotation(session.id);

    // Outside grace: the same original token now reads as replay.
    const outsideGrace = await apiRequest("/auth/session/refresh", { method: "POST", refreshToken });
    expect(outsideGrace.status).toBe(401);
    expect(String(outsideGrace.data.error)).toMatch(/reuse/i);

    const deleted = await prisma.session.findUnique({ where: { id: session.id } });
    expect(deleted).toBeNull();
  });

  it("TEST 7: access and refresh tokens cannot be used in each other's place", async () => {
    const { accessToken, refreshToken } = await login(nextEmail("7"));

    const refreshAsAccess = await apiRequest("/auth/me", { token: refreshToken });
    expect(refreshAsAccess.status).toBe(401);

    const accessAsRefresh = await apiRequest("/auth/session/refresh", { method: "POST", refreshToken: accessToken });
    expect(accessAsRefresh.status).toBe(401);
  });

  it("TEST 8: a refresh token whose sub doesn't match the session's actual owner is rejected without rotating or revoking", async () => {
    const a = await login(nextEmail("8a"));
    const b = await login(nextEmail("8b"));

    // Forged: sessionId points at A's real session (with A's real, current
    // jti), but sub claims to be B.
    const forged = signRefreshToken({ sub: b.user.id, sessionId: a.session.id }, a.refreshTokenId);
    const res = await apiRequest("/auth/session/refresh", { method: "POST", refreshToken: forged });
    expect(res.status).toBe(401);

    const stillA = await prisma.session.findUniqueOrThrow({ where: { id: a.session.id } });
    expect(stillA.currentRefreshTokenId).toBe(a.refreshTokenId); // unchanged -- no rotation
    expect(stillA.previousRefreshTokenId).toBeNull(); // never touched
  });

  it("TEST 9: a revoked (deleted) session cannot refresh", async () => {
    const { session, refreshToken } = await login(nextEmail("9"));
    await prisma.session.delete({ where: { id: session.id } });

    const res = await apiRequest("/auth/session/refresh", { method: "POST", refreshToken });
    expect(res.status).toBe(401);
  });

  it("TEST 10: logout invalidates the refresh token", async () => {
    const { accessToken, refreshToken } = await login(nextEmail("10"));

    const logout = await apiRequest("/auth/logout", { method: "POST", token: accessToken });
    expect(logout.status).toBe(200);

    const res = await apiRequest("/auth/session/refresh", { method: "POST", refreshToken });
    expect(res.status).toBe(401);
  });

  it("TEST 11: a deleted user's cascaded session cannot refresh", async () => {
    const { user, refreshToken } = await login(nextEmail("11"));

    // Mirrors exactly what DELETE /users/:id does internally
    // (server/src/routes/users.ts): Credential/Session cleared, then User.
    await prisma.$transaction([
      prisma.credential.deleteMany({ where: { userId: user.id } }),
      prisma.session.deleteMany({ where: { userId: user.id } }),
      prisma.user.delete({ where: { id: user.id } }),
    ]);

    const res = await apiRequest("/auth/session/refresh", { method: "POST", refreshToken });
    expect(res.status).toBe(401);
  });

  it("TEST 12: an expired session cannot refresh, and expiresAt is never touched by a refresh attempt", async () => {
    const { session, refreshToken, refreshTokenId } = await login(nextEmail("12"));
    const expiredAt = new Date(Date.now() - 1_000);
    await prisma.session.update({ where: { id: session.id }, data: { expiresAt: expiredAt } });

    const res = await apiRequest("/auth/session/refresh", { method: "POST", refreshToken });
    expect(res.status).toBe(401);

    const stillExpired = await prisma.session.findUniqueOrThrow({ where: { id: session.id } });
    expect(stillExpired.expiresAt.getTime()).toBe(expiredAt.getTime());
    expect(stillExpired.currentRefreshTokenId).toBe(refreshTokenId); // no rotation attempted
  });

  it("TEST 13: a malformed refresh cookie fails safely, never a 500", async () => {
    const res = await apiRequest("/auth/session/refresh", { method: "POST", refreshToken: "not-a-jwt-at-all" });
    expect(res.status).toBe(401);
  });

  it("TEST 14: a token signed with the wrong secret is rejected", async () => {
    const bogus = jwt.sign({ sub: "x", sessionId: "y", type: "refresh" }, "definitely-the-wrong-secret", {
      expiresIn: "30d",
      jwtid: "bogus-jti",
    });
    const res = await apiRequest("/auth/session/refresh", { method: "POST", refreshToken: bogus });
    expect(res.status).toBe(401);
  });

  it("TEST 15: rotation preserves existing cookie security flags", async () => {
    const { refreshToken } = await login(nextEmail("15"));
    const { status, setCookies } = await rawRefresh(refreshToken);
    expect(status).toBe(200);
    expect(setCookies.length).toBeGreaterThanOrEqual(2);

    const refreshCookie = setCookies.find((c) => c.startsWith("refreshToken="));
    const accessCookie = setCookies.find((c) => c.startsWith("accessToken="));
    expect(refreshCookie).toBeDefined();
    expect(accessCookie).toBeDefined();

    for (const cookie of [refreshCookie!, accessCookie!]) {
      expect(cookie).toMatch(/HttpOnly/i);
      expect(cookie).toMatch(/SameSite=Lax/i);
      expect(cookie).toMatch(/Max-Age=\d+/i);
      if (env.rpOrigin.startsWith("https")) {
        expect(cookie).toMatch(/;\s*Secure/i);
      } else {
        expect(cookie).not.toMatch(/;\s*Secure/i);
      }
    }
  });

  it("TEST 17: replay revocation and its audit events commit together, exactly once, even under concurrent replays", async () => {
    const { session, refreshToken } = await login(nextEmail("17"));
    expect((await apiRequest("/auth/session/refresh", { method: "POST", refreshToken })).status).toBe(200);
    await backdateRotation(session.id);

    const replays = await Promise.all(
      Array.from({ length: 5 }, () => apiRequest("/auth/session/refresh", { method: "POST", refreshToken })),
    );
    for (const r of replays) expect(r.status).toBe(401);
    expect(await prisma.session.findUnique({ where: { id: session.id } })).toBeNull();

    const events = await prisma.auditLog.findMany({ where: { entityType: "Session", entityId: session.id } });
    expect(events.filter((e) => e.event === "REFRESH_TOKEN_REUSE_DETECTED")).toHaveLength(1);
    expect(events.filter((e) => e.event === "SESSION_REVOKED")).toHaveLength(1);
  });

  it("TEST 18: a disabled or suspended user's current, never-used refresh token is rejected without rotating", async () => {
    for (const status of ["DISABLED", "SUSPENDED"] as const) {
      const { user, session, refreshToken, refreshTokenId } = await login(nextEmail(`18-${status}`));
      await prisma.user.update({ where: { id: user.id }, data: { status } });
      const res = await apiRequest("/auth/session/refresh", { method: "POST", refreshToken });
      expect(res.status).toBe(401);
      const row = await prisma.session.findUniqueOrThrow({ where: { id: session.id } });
      expect(row.currentRefreshTokenId).toBe(refreshTokenId);
      expect(row.previousRefreshTokenId).toBeNull();
    }
  });

  it("TEST 19: logout is audited and its refresh token can't be revived", async () => {
    const { session, accessToken, refreshToken } = await login(nextEmail("19"));
    expect((await apiRequest("/auth/logout", { method: "POST", token: accessToken })).status).toBe(200);
    expect(await prisma.auditLog.count({ where: { entityId: session.id, event: "LOGOUT" } })).toBe(1);
    expect((await apiRequest("/auth/session/refresh", { method: "POST", refreshToken })).status).toBe(401);
    expect((await apiRequest("/auth/me", { token: accessToken })).status).toBe(401);
  });

  it("TEST 20: a correctly signed refresh token without the session issuer/audience claims is rejected", async () => {
    const { user, session, refreshTokenId } = await login(nextEmail("20"));
    const legacyShape = jwt.sign({ sub: user.id, sessionId: session.id, type: "refresh" }, env.jwtRefreshSecret, {
      expiresIn: "30d",
      jwtid: refreshTokenId,
    });
    expect((await apiRequest("/auth/session/refresh", { method: "POST", refreshToken: legacyShape })).status).toBe(401);
    const row = await prisma.session.findUniqueOrThrow({ where: { id: session.id } });
    expect(row.currentRefreshTokenId).toBe(refreshTokenId);
  });

  // TEST 16 (database failure during refresh) is intentionally not
  // implemented: this test harness has no existing fault-injection
  // mechanism (no mockable Prisma client swap, no proxy in front of
  // Postgres), and building one solely for this single scenario would be
  // exactly the "complicated DB-failure framework" the task explicitly says
  // to avoid when impractical. The relevant safety property --
  // rotateRefreshToken only ever calls session.delete on a verified replay
  // condition (session found, CAS lost, previousRefreshTokenId doesn't
  // match or grace has elapsed), never on a caught/unknown error, and any
  // *other* thrown error (e.g. a genuine DB outage) propagates unchanged to
  // the route's existing top-level error handling rather than being
  // reinterpreted as "no session"/"replay" -- is verified by direct code
  // inspection of server/src/lib/refreshRotation.ts and documented in the
  // P0-4 report rather than exercised by a live induced failure here.
});
