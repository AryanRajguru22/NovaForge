import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  startTestServer,
  stopTestServer,
  apiRequest,
  createUserWithToken,
  cleanupUsers,
  cleanupPolicies,
  runSuffix,
} from "./testServer.js";
import { prisma } from "../src/lib/prisma.js";
import { generateRefreshTokenId, signAccessToken } from "../src/lib/jwt.js";

// requireTrust (server/src/middleware/requireTrust.ts) gates on the same
// effective (decayed) trust that identity assertions expose
// (server/src/lib/identityAssertion.ts), via the shared decayedTrustLevel()
// helper (server/src/lib/trust.ts) -- not the raw, possibly-stale stored
// Session.trustLevel. This exercises that gate directly against sessions with
// a controlled lastVerifiedAt, rather than relying on wall-clock decay during
// the test run (server/test/trust-gating.test.ts covers the pre-existing,
// non-decay case: an explicit low trustLevel on an otherwise-fresh session).
describe("trust gating evaluates effective (decayed) trust, not the raw stored value", () => {
  const emailFor = (n: number) => `trust-gate-decay-${n}-${runSuffix}@example.com`;
  const allEmails = Array.from({ length: 4 }, (_, i) => emailFor(i));
  const actionType = `test:trust-gate-decay-${runSuffix}`;

  let caseCounter = 0;

  beforeAll(async () => {
    await startTestServer();
    await cleanupUsers(allEmails);
    await cleanupPolicies([actionType]);
    await prisma.approvalPolicy.create({
      data: { actionType, quorumType: "N_OF_M", minApprovals: 1, eligibleRoles: ["APPROVER"], escalationTimeoutSec: 300 },
    });
  });

  afterAll(async () => {
    await prisma.approvalRequest.deleteMany({ where: { policy: { actionType } } });
    await prisma.sensitiveAction.deleteMany({ where: { requestedBy: { email: { in: allEmails } } } });
    await cleanupPolicies([actionType]);
    await cleanupUsers(allEmails);
    await stopTestServer();
  });

  /** A session with a controlled lastVerifiedAt, so decay is deterministic rather than wall-clock-dependent. */
  async function sessionVerifiedHoursAgo(hoursAgo: number, trustLevel = 100) {
    const { user } = await createUserWithToken({ email: emailFor(caseCounter++), role: "MEMBER" });
    const refreshTokenId = generateRefreshTokenId();
    const session = await prisma.session.create({
      data: {
        userId: user.id,
        deviceId: "test-device",
        trustLevel,
        lastVerifiedAt: new Date(Date.now() - hoursAgo * 3_600_000),
        expiresAt: new Date(Date.now() + 24 * 3_600_000),
        currentRefreshTokenId: refreshTokenId,
      },
    });
    return { user, session, accessToken: signAccessToken({ sub: user.id, sessionId: session.id }) };
  }

  async function attemptAction(accessToken: string) {
    return apiRequest("/actions", {
      method: "POST",
      token: accessToken,
      body: { type: actionType, payload: { amount: 1 } },
    });
  }

  async function expectSessionUnchanged(session: { id: string; trustLevel: number; lastVerifiedAt: Date; currentRefreshTokenId: string | null }) {
    const row = await prisma.session.findUniqueOrThrow({ where: { id: session.id } });
    expect(row.trustLevel).toBe(session.trustLevel);
    expect(row.lastVerifiedAt.getTime()).toBe(session.lastVerifiedAt.getTime());
    expect(row.currentRefreshTokenId).toBe(session.currentRefreshTokenId);
  }

  it("a fresh session (no decay) passes the gate at full stored trust", async () => {
    const { session, accessToken } = await sessionVerifiedHoursAgo(0);
    const res = await attemptAction(accessToken);
    expect(res.status).toBe(201);
    await expectSessionUnchanged(session);
  });

  it("a partially decayed session still above threshold passes, gated on the decayed value", async () => {
    // 100 - (2h * 5/h) = 90, still >= the 50 minimum.
    const { session, accessToken } = await sessionVerifiedHoursAgo(2, 100);
    const res = await attemptAction(accessToken);
    expect(res.status).toBe(201);
    await expectSessionUnchanged(session);
  });

  it("a sufficiently stale session fails the threshold even though the stored trustLevel is still full", async () => {
    // 100 - (11h * 5/h) = 45, below the 50 minimum -- but the stored value is
    // untouched 100. A gate reading the raw stored value would wrongly pass this.
    const { session, accessToken } = await sessionVerifiedHoursAgo(11, 100);
    const res = await attemptAction(accessToken);
    expect(res.status).toBe(403);
    expect(res.data.error).toMatch(/trust/i);
    expect(res.data.trustLevel).toBe(45);
    expect(res.data.required).toBe(50);
    await expectSessionUnchanged(session);
  });

  it("repeated trust checks are side-effect free: back-to-back gated calls never mutate the session", async () => {
    const { session, accessToken } = await sessionVerifiedHoursAgo(11, 100);
    const first = await attemptAction(accessToken);
    const second = await attemptAction(accessToken);
    expect(first.status).toBe(403);
    expect(second.status).toBe(403);
    expect(first.data.trustLevel).toBe(second.data.trustLevel);
    await expectSessionUnchanged(session);
  });
});
