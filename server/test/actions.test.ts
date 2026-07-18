import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { startTestServer, stopTestServer, apiRequest, createUserWithToken, cleanupUsers, cleanupPolicies, runSuffix } from "./testServer.js";
import { prisma } from "../src/lib/prisma.js";

describe("sensitive action creation", () => {
  const emails = [`action-creator-${runSuffix}@example.com`];
  const actionType = "test:action-crud";
  let creatorToken: string;
  let creatorId: string;
  let policyId: string;

  beforeAll(async () => {
    await startTestServer();
    await cleanupUsers(emails);
    await cleanupPolicies([actionType]);
    const { user, token } = await createUserWithToken({ email: emails[0] });
    creatorId = user.id;
    creatorToken = token;
    const policy = await prisma.approvalPolicy.create({
      data: { actionType, quorumType: "N_OF_M", minApprovals: 1, eligibleRoles: ["ADMIN"], escalationTimeoutSec: 300 },
    });
    policyId = policy.id;
  });

  afterAll(async () => {
    await prisma.approvalRequest.deleteMany({ where: { policyId } });
    await prisma.sensitiveAction.deleteMany({ where: { requestedById: creatorId } });
    await cleanupPolicies([actionType]);
    await cleanupUsers(emails);
    await stopTestServer();
  });

  it("rejects creation when no policy matches the action type", async () => {
    const { status, data } = await apiRequest("/actions", {
      method: "POST",
      token: creatorToken,
      body: { type: "test:unconfigured-type", payload: { ok: true } },
    });
    expect(status).toBe(400);
    expect(data.error).toMatch(/No approval policy configured/);
  });

  it("creates an action and a linked pending approval request", async () => {
    const { status, data } = await apiRequest("/actions", {
      method: "POST",
      token: creatorToken,
      body: { type: actionType, payload: { amount: 500 } },
    });
    expect(status).toBe(201);
    expect(data.action.status).toBe("PENDING");
    expect(data.approvalRequest.status).toBe("PENDING");

    const fetched = await apiRequest(`/actions/${data.action.id}`, { token: creatorToken });
    expect(fetched.status).toBe(200);
    expect(fetched.data.approvalRequest.policy.actionType).toBe(actionType);
  });
});
