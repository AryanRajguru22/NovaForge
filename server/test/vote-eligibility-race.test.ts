import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  startTestServer,
  stopTestServer,
  apiRequest,
  createUserWithToken,
  addMockPasskey,
  authenticatorFor,
  cleanupUsers,
  cleanupPolicies,
  runSuffix,
  createApprovalRequestWithSnapshot,
} from "./testServer.js";
import { computeSubjectDigest } from "../src/lib/approvalSignature.js";
import { prisma } from "../src/lib/prisma.js";
import { takeChallenge } from "../src/lib/challengeStore.js";

// The vote route checks eligibility once against a pre-transaction snapshot
// of the request's policy. If escalation reassigns the request to a fallback
// policy whose eligible roles exclude the voter after that snapshot but
// before the vote's row lock, the vote must be refused against the policy it
// actually locks -- not recorded under the stale one.
//
// Deterministic, no timing windows: the test itself holds the
// ApprovalRequest row lock and reassigns the policy inside that (still
// uncommitted) transaction. The vote's snapshot read therefore still sees the
// original policy and passes; the vote then blocks on FOR UPDATE, which the
// test observes in pg_stat_activity before committing the reassignment.
describe("vote eligibility is re-checked against the locked policy", () => {
  const emails = [`elig-race-creator-${runSuffix}@example.com`, `elig-race-approver-${runSuffix}@example.com`];
  const primaryType = `test:elig-race-primary-${runSuffix}`;
  const fallbackType = `test:elig-race-fallback-${runSuffix}`;

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

    // Fallback excludes APPROVER entirely.
    fallbackPolicy = await prisma.approvalPolicy.create({
      data: { actionType: fallbackType, quorumType: "N_OF_M", minApprovals: 1, eligibleRoles: ["ADMIN"], escalationTimeoutSec: 300 },
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

  async function waitForVoteBlockedOnRowLock(timeoutMs = 10_000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const [{ count }] = await prisma.$queryRaw<{ count: bigint }[]>`
        SELECT COUNT(*)::bigint AS count FROM pg_stat_activity
        WHERE wait_event_type = 'Lock'
          AND query ILIKE '%FROM "ApprovalRequest"%'
          AND query ILIKE '%FOR UPDATE%'`;
      if (count > 0n) return;
      await new Promise((r) => setTimeout(r, 25));
    }
    throw new Error("vote never reached the ApprovalRequest row lock");
  }

  it("a policy reassigned to exclude the voter between snapshot and lock rejects the vote and records nothing", async () => {
    const action = await prisma.sensitiveAction.create({
      data: { type: primaryType, payload: { amount: 3 }, payloadDigest: computeSubjectDigest(primaryType, { amount: 3 }), requestedById: creator.id },
    });
    const request = await createApprovalRequestWithSnapshot({ actionId: action.id, policyId: primaryPolicy.id, expiresAt: new Date(Date.now() + 60_000) });

    // Under the original policy the voter is eligible: options succeed and the statement is signed.
    const options = await apiRequest(`/approvals/${request.id}/options`, {
      method: "POST",
      token: approver.token,
      body: { decision: "APPROVE" },
    });
    expect(options.status).toBe(200);
    const response = authenticatorFor(approver.id).createAssertion(options.data.challenge);
    const credentialBefore = await prisma.credential.findFirstOrThrow({ where: { userId: approver.id, type: "PASSKEY" } });

    let vote: Promise<{ status: number; data: any }> | undefined;
    await prisma.$transaction(
      async (tx) => {
        await tx.$queryRaw`SELECT "id" FROM "ApprovalRequest" WHERE "id" = ${request.id} FOR UPDATE`;
        // Mirrors escalation's fallback reassignment; uncommitted, so invisible to the vote's snapshot.
        await tx.approvalRequest.updateMany({
          where: { id: request.id, status: "PENDING" },
          data: { policyId: fallbackPolicy.id, escalationLevel: 1 },
        });

        vote = apiRequest(`/approvals/${request.id}/vote`, {
          method: "POST",
          token: approver.token,
          body: { decision: "APPROVE", response },
        });
        await waitForVoteBlockedOnRowLock();
      },
      { maxWait: 5_000, timeout: 12_000 },
    );

    const voteResult = await vote!;
    expect(voteResult.status).toBe(403);
    expect(voteResult.data.error).toBe("Forbidden: You are not eligible to approve this action");
    // The pre-transaction eligibility check runs before the signed statement
    // is consumed; a consumed statement proves the refusal came from the
    // locked re-check, not the snapshot fast-path.
    expect(takeChallenge(`vote:${approver.id}:${request.id}:${options.data.challenge}`)).toBeUndefined();

    expect(await prisma.approvalVote.count({ where: { requestId: request.id } })).toBe(0);
    const dbRequest = await prisma.approvalRequest.findUniqueOrThrow({ where: { id: request.id } });
    expect(dbRequest.status).toBe("PENDING");
    expect(dbRequest.policyId).toBe(fallbackPolicy.id);
    expect(dbRequest.escalationLevel).toBe(1);
    const dbAction = await prisma.sensitiveAction.findUniqueOrThrow({ where: { id: action.id } });
    expect(dbAction.status).toBe("PENDING");

    // Fail closed before any write: no counter bump, no audit event.
    const credentialAfter = await prisma.credential.findUniqueOrThrow({ where: { id: credentialBefore.id } });
    expect(credentialAfter.counter).toBe(credentialBefore.counter);
    expect(await prisma.auditLog.count({ where: { entityType: "ApprovalVote", actorId: approver.id } })).toBe(0);
  });
});
