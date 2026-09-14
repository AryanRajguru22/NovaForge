import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { startTestServer, stopTestServer, apiRequest, createUserWithToken, addMockPasskey, cleanupUsers, cleanupPolicies, runSuffix, castVote as castSignedVote } from "./testServer.js";
import { computeSubjectDigest } from "../src/lib/approvalSignature.js";
import { prisma } from "../src/lib/prisma.js";
import { checkEscalations } from "../src/lib/escalation.js";

describe("P0-2: vote vs. expiry/escalation race", () => {
  const emails = [`expiry-creator-${runSuffix}@example.com`, `expiry-approver-${runSuffix}@example.com`];
  const actionType = `test:expiry-race-${runSuffix}`;

  let creator: { id: string };
  let approver: { id: string; token: string };

  beforeAll(async () => {
    await startTestServer();
    await cleanupUsers(emails);
    await cleanupPolicies([actionType]);

    const c = await createUserWithToken({ email: emails[0], role: "MEMBER" });
    const a = await createUserWithToken({ email: emails[1], role: "APPROVER" });
    creator = { id: c.user.id };
    approver = { id: a.user.id, token: a.token };
    await addMockPasskey(approver.id);

    await prisma.approvalPolicy.create({
      data: { actionType, quorumType: "N_OF_M", minApprovals: 1, eligibleRoles: ["APPROVER"], escalationTimeoutSec: 300 },
    });
  });

  afterAll(async () => {
    await prisma.approvalVote.deleteMany({ where: { request: { policy: { actionType } } } });
    await prisma.approvalRequest.deleteMany({ where: { policy: { actionType } } });
    await prisma.sensitiveAction.deleteMany({ where: { requestedBy: { email: { in: emails } } } });
    await cleanupPolicies([actionType]);
    await cleanupUsers(emails);
    await stopTestServer();
  });

  // Rather than waiting on escalation's real 5-second setInterval timer
  // (server/src/lib/escalation.ts), this test invokes checkEscalations()
  // directly -- exported specifically for this purpose, with no change to
  // its production behavior -- and races it against a real vote HTTP request
  // via Promise.all, against a request whose expiresAt is already in the
  // past. This proves the invariant that actually matters end-to-end:
  // regardless of which of the two "wins", the request is never left in (or
  // returned to) anything but EXPIRED, and the racing vote never succeeds
  // against it and never 500s.
  //
  // What this test does NOT, and cannot without a larger refactor, cleanly
  // isolate: since the vote route's own pre-transaction fast-path check
  // (server/src/routes/approvals.ts, the outer status/expiresAt check before
  // the transaction) also independently rejects a request whose expiresAt
  // has already passed, an already-past expiresAt at test start means the
  // vote is very likely to be bounced by that fast-path before it ever
  // reaches the row lock and this change's authoritative, in-transaction
  // re-validation. Forcing the vote specifically through the locked path
  // (rather than the fast-path) would require either a sub-millisecond
  // timing window -- exactly what "don't make the test timing-dependent or
  // flaky" rules out -- or an injectable clock, which is out of P0-2's
  // scope. The locked, in-transaction re-validation path is already directly
  // exercised by the vote-vs-vote races in concurrent-quorum.test.ts; this
  // test's job is specifically the vote-vs-escalation interaction, at
  // whichever gate ends up catching it, and the invariant it proves (never a
  // resurrected EXPIRED request, never a 500) holds either way.
  it("TEST 7: a request already past its expiry cannot be resurrected by a vote racing the escalation check", async () => {
    const action = await prisma.sensitiveAction.create({
      data: { type: actionType, payload: { amount: 7 }, payloadDigest: computeSubjectDigest(actionType, { amount: 7 }), requestedById: creator.id },
    });
    const policy = await prisma.approvalPolicy.findUniqueOrThrow({ where: { actionType } });
    const request = await prisma.approvalRequest.create({
      data: { actionId: action.id, policyId: policy.id, expiresAt: new Date(Date.now() - 1000) },
    });

    const castVote = () => castSignedVote(request.id, approver, "APPROVE");

    const [voteResult] = await Promise.all([castVote(), checkEscalations()]);

    // expiresAt is already in the past for both racing sides, so the vote
    // can never legitimately succeed here -- it must be rejected by either
    // the fast-path expiry check or the locked in-transaction re-validation,
    // never a 500, and never a 200 that would mean it resolved an already
    // (or about to be) expired request.
    expect(voteResult.status).not.toBe(500);
    expect(voteResult.status).not.toBe(200);

    const dbRequest = await prisma.approvalRequest.findUnique({ where: { id: request.id } });
    const dbAction = await prisma.sensitiveAction.findUnique({ where: { id: action.id } });
    expect(dbRequest?.status).toBe("EXPIRED");
    expect(dbAction?.status).toBe("EXPIRED");

    // The vote must never have been inserted against an already-expired (or
    // expiring-in-the-same-race) request.
    const votes = await prisma.approvalVote.findMany({ where: { requestId: request.id } });
    expect(votes).toHaveLength(0);

    const expiredAudit = await prisma.auditLog.count({
      where: { entityType: "ApprovalRequest", entityId: request.id, event: "REQUEST_EXPIRED" },
    });
    expect(expiredAudit).toBe(1);
  });
});

// A second, independent race: a vote against escalation's *fallback-policy
// reassignment* (as opposed to TEST 7's expiry/EXPIRED race above). Racing
// this specific interaction through the real HTTP vote route against an
// already-past expiresAt runs into the same problem TEST 7's own comment
// documents -- the vote's pre-transaction fast-path check would almost
// always reject it before it ever reaches the row lock, for the same reason
// escalation's own candidate scan needs expiresAt already in the past to act
// at all. That would make "did the vote actually see a reassigned policy"
// untestable without either a flaky sub-millisecond window or bypassing the
// vote route's own fast-path check outside of what P0-2 changed.
//
// This test avoids that problem entirely by not depending on wall-clock
// expiry at all: expiresAt is set comfortably in the future (so the vote's
// fast-path check and its locked re-validation both pass, regardless of
// ordering), and the "reassignment" side of the race is driven directly via
// a transaction that deliberately mirrors the exact shape of the fallback-
// reassignment block inside checkEscalations() (server/src/lib/
// escalation.ts) -- same conditional updateMany, same WHERE status='PENDING'
// guard -- rather than by waiting for escalation's own time-gated candidate
// scan to pick the row up. That makes the race genuinely concurrent and
// fully deterministic in outcome *pattern*, with no dependency on timing.
describe("P0-2: vote vs. escalation's fallback-policy reassignment race", () => {
  const emails = [`policy-race-creator-${runSuffix}@example.com`, `policy-race-approver-${runSuffix}@example.com`];
  const primaryType = `test:policy-race-primary-${runSuffix}`;
  const fallbackType = `test:policy-race-fallback-${runSuffix}`;

  let creator: { id: string };
  let approver: { id: string; token: string };
  let primaryPolicy: { id: string };
  let fallbackPolicy: { id: string };

  beforeAll(async () => {
    await startTestServer();
    await cleanupUsers(emails);
    await cleanupPolicies([primaryType, fallbackType]);

    const c = await createUserWithToken({ email: emails[0], role: "MEMBER" });
    const a = await createUserWithToken({ email: emails[1], role: "APPROVER" });
    creator = { id: c.user.id };
    approver = { id: a.user.id, token: a.token };
    await addMockPasskey(approver.id);

    // fallback requires 5 approvals -- a single vote can never resolve it
    // alone -- while primary resolves on the first vote (minApprovals: 1).
    // That asymmetry is what makes the two possible race outcomes cleanly
    // distinguishable below (APPROVED-under-primary vs. still-PENDING-under-
    // fallback), rather than proving only that *a* policy was used.
    fallbackPolicy = await prisma.approvalPolicy.create({
      data: { actionType: fallbackType, quorumType: "N_OF_M", minApprovals: 5, eligibleRoles: ["APPROVER"], escalationTimeoutSec: 300 },
    });
    primaryPolicy = await prisma.approvalPolicy.create({
      data: {
        actionType: primaryType,
        quorumType: "N_OF_M",
        minApprovals: 1,
        eligibleRoles: ["APPROVER"],
        escalationTimeoutSec: 300,
        fallbackPolicyId: fallbackPolicy.id,
      },
    });
  });

  afterAll(async () => {
    await prisma.approvalVote.deleteMany({ where: { request: { policy: { actionType: { in: [primaryType, fallbackType] } } } } });
    await prisma.approvalRequest.deleteMany({ where: { policy: { actionType: { in: [primaryType, fallbackType] } } } });
    await prisma.sensitiveAction.deleteMany({ where: { requestedBy: { email: { in: emails } } } });
    await cleanupPolicies([primaryType, fallbackType]);
    await cleanupUsers(emails);
    await stopTestServer();
  });

  /** Deliberately mirrors checkEscalations()'s own fallback-reassignment
   * transaction (server/src/lib/escalation.ts) -- same shape, same guard --
   * so this test drives a real, concurrent reassignment without depending on
   * escalation's own time-gated candidate scan. */
  async function reassignToFallback(requestId: string, newPolicyId: string, newExpiresAt: Date): Promise<boolean> {
    let success = false;
    await prisma.$transaction(async (tx) => {
      const updated = await tx.approvalRequest.updateMany({
        where: { id: requestId, status: "PENDING" },
        data: { policyId: newPolicyId, expiresAt: newExpiresAt },
      });
      success = updated.count === 1;
    });
    return success;
  }

  it("a vote racing a concurrent fallback-policy reassignment always evaluates ONE coherent policy, never a hybrid of both", async () => {
    const action = await prisma.sensitiveAction.create({
      data: { type: primaryType, payload: { amount: 1 }, payloadDigest: computeSubjectDigest(primaryType, { amount: 1 }), requestedById: creator.id },
    });
    const request = await prisma.approvalRequest.create({
      data: { actionId: action.id, policyId: primaryPolicy.id, expiresAt: new Date(Date.now() + 60_000) },
    });

    const castVote = () => castSignedVote(request.id, approver, "APPROVE");

    const [voteResult] = await Promise.all([
      castVote(),
      reassignToFallback(request.id, fallbackPolicy.id, new Date(Date.now() + 300_000)),
    ]);

    // A single vote against a policy requiring only 1 approval always
    // succeeds at the HTTP layer regardless of which side of the race wins --
    // either it resolves the request outright (primary won the lock first),
    // or it's accepted as a PENDING vote evaluated under the now-reassigned
    // fallback policy (reassignment won the lock first). Never a 400/500.
    expect(voteResult.status).toBe(200);

    const dbRequest = await prisma.approvalRequest.findUnique({ where: { id: request.id } });

    // Exactly two coherent outcomes are possible; nothing in between:
    //  - the vote's transaction won the lock first, saw policyId still
    //    pointing at primary (minApprovals=1), and resolved APPROVED under
    //    primary's rules alone -- the reassignment then finds the row no
    //    longer PENDING and never takes effect, so policyId stays primary's.
    //  - the reassignment won the lock first, so by the time the vote's
    //    transaction re-reads the row under its own lock, policyId already
    //    points at fallback (minApprovals=5) -- one vote isn't enough, so it
    //    stays PENDING, evaluated entirely under fallback's rules.
    // A bug that used a stale, pre-lock policy snapshot instead of re-reading
    // it under the lock could produce a third, incoherent combination here
    // (e.g. APPROVED while policyId already reads as fallback's id, which
    // requires 5 votes) -- this assertion rejects exactly that combination.
    const wonUnderPrimary = dbRequest?.status === "APPROVED" && dbRequest?.policyId === primaryPolicy.id;
    const wonUnderFallback = dbRequest?.status === "PENDING" && dbRequest?.policyId === fallbackPolicy.id;
    expect(wonUnderPrimary || wonUnderFallback).toBe(true);

    const votes = await prisma.approvalVote.findMany({ where: { requestId: request.id } });
    expect(votes).toHaveLength(1);
  });
});
