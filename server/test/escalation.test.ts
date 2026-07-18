import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { startTestServer, stopTestServer, apiRequest, createUserWithToken, cleanupUsers, cleanupPolicies, runSuffix } from "./testServer.js";
import { prisma } from "../src/lib/prisma.js";

// The escalation service (src/lib/escalation.ts) polls every 5s, so these tests
// use a 1s escalationTimeoutSec and wait past one poll interval.
async function waitForEscalationTick() {
  await new Promise((resolve) => setTimeout(resolve, 6500));
}

describe("approval request escalation", () => {
  const emails = [`escalation-creator-${runSuffix}@example.com`];
  const primaryType = "test:escalation-primary";
  const fallbackType = "test:escalation-fallback";
  const noFallbackType = "test:escalation-none";
  let creatorToken: string;

  beforeAll(async () => {
    await startTestServer();
    await cleanupUsers(emails);
    await cleanupPolicies([primaryType, fallbackType, noFallbackType]);
    creatorToken = (await createUserWithToken({ email: emails[0] })).token;
  }, 20000);

  afterAll(async () => {
    await cleanupPolicies([primaryType, fallbackType, noFallbackType]);
    await cleanupUsers(emails);
    await stopTestServer();
  });

  it("escalates a request to its fallback policy once the timeout passes", async () => {
    const fallback = await prisma.approvalPolicy.create({
      data: { actionType: fallbackType, quorumType: "N_OF_M", minApprovals: 1, eligibleRoles: ["ADMIN"], escalationTimeoutSec: 300 },
    });
    const primary = await prisma.approvalPolicy.create({
      data: {
        actionType: primaryType,
        quorumType: "N_OF_M",
        minApprovals: 1,
        eligibleRoles: ["APPROVER"],
        escalationTimeoutSec: 1,
        fallbackPolicyId: fallback.id,
      },
    });

    const { data: created } = await apiRequest("/actions", {
      method: "POST",
      token: creatorToken,
      body: { type: primaryType, payload: { amount: 1 } },
    });
    const requestId = created.approvalRequest.id;

    await waitForEscalationTick();

    const updated = await prisma.approvalRequest.findUnique({ where: { id: requestId } });
    expect(updated?.status).toBe("PENDING");
    expect(updated?.policyId).toBe(fallback.id);

    const escalationAudit = await prisma.auditLog.findFirst({
      where: { entityType: "ApprovalRequest", entityId: requestId, event: "ESCALATION_TRIGGERED" },
    });
    expect(escalationAudit).not.toBeNull();

    await prisma.approvalRequest.deleteMany({ where: { id: requestId } });
    await prisma.sensitiveAction.deleteMany({ where: { id: created.action.id } });
    await prisma.approvalPolicy.deleteMany({ where: { id: { in: [primary.id, fallback.id] } } });
  }, 20000);

  it("expires a request with no fallback policy once the timeout passes", async () => {
    const policy = await prisma.approvalPolicy.create({
      data: { actionType: noFallbackType, quorumType: "N_OF_M", minApprovals: 1, eligibleRoles: ["APPROVER"], escalationTimeoutSec: 1 },
    });

    const { data: created } = await apiRequest("/actions", {
      method: "POST",
      token: creatorToken,
      body: { type: noFallbackType, payload: { amount: 1 } },
    });
    const requestId = created.approvalRequest.id;

    await waitForEscalationTick();

    const updatedRequest = await prisma.approvalRequest.findUnique({ where: { id: requestId } });
    const updatedAction = await prisma.sensitiveAction.findUnique({ where: { id: created.action.id } });
    expect(updatedRequest?.status).toBe("EXPIRED");
    expect(updatedAction?.status).toBe("EXPIRED");

    const expiredAudit = await prisma.auditLog.findFirst({
      where: { entityType: "ApprovalRequest", entityId: requestId, event: "REQUEST_EXPIRED" },
    });
    expect(expiredAudit).not.toBeNull();

    await prisma.approvalRequest.deleteMany({ where: { id: requestId } });
    await prisma.sensitiveAction.deleteMany({ where: { id: created.action.id } });
    await prisma.approvalPolicy.deleteMany({ where: { id: policy.id } });
  }, 20000);
});
