import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { startTestServer, stopTestServer, apiRequest, createUserWithToken, cleanupUsers, cleanupPolicies, runSuffix } from "./testServer.js";
import { prisma } from "../src/lib/prisma.js";

describe("policy management", () => {
  const emails = [
    `policy-admin-${runSuffix}@example.com`,
    `policy-member-${runSuffix}@example.com`,
    `policy-superadmin-${runSuffix}@example.com`,
  ];
  const actionType = "test:policy-crud";
  const referencedActionType = "test:policy-delete-referenced";
  const superAdminActionType = "test:policy-superadmin-crud";
  let adminToken: string;
  let memberToken: string;
  let superAdminToken: string;
  let createdPolicyId: string;

  beforeAll(async () => {
    await startTestServer();
    await cleanupUsers(emails);
    await cleanupPolicies([actionType, referencedActionType, superAdminActionType]);
    adminToken = (await createUserWithToken({ email: emails[0], role: "ADMIN" })).token;
    memberToken = (await createUserWithToken({ email: emails[1], role: "MEMBER" })).token;
    superAdminToken = (await createUserWithToken({ email: emails[2], role: "SUPER_ADMIN" })).token;
  });

  afterAll(async () => {
    await cleanupPolicies([actionType, referencedActionType, superAdminActionType]);
    await cleanupUsers(emails);
    await stopTestServer();
  });

  it("rejects policy creation from a non-admin", async () => {
    const { status } = await apiRequest("/policies", {
      method: "POST",
      token: memberToken,
      body: { actionType, quorumType: "N_OF_M", minApprovals: 1, eligibleRoles: ["ADMIN"] },
    });
    expect(status).toBe(403);
  });

  it("lets an admin create a policy", async () => {
    const { status, data } = await apiRequest("/policies", {
      method: "POST",
      token: adminToken,
      body: { actionType, quorumType: "N_OF_M", minApprovals: 2, eligibleRoles: ["ADMIN"] },
    });
    expect(status).toBe(201);
    expect(data.actionType).toBe(actionType);
    createdPolicyId = data.id;
  });

  it("lets a super admin do everything an admin can, including creating a policy", async () => {
    const { status, data } = await apiRequest("/policies", {
      method: "POST",
      token: superAdminToken,
      body: { actionType: superAdminActionType, quorumType: "N_OF_M", minApprovals: 1, eligibleRoles: ["ADMIN"] },
    });
    expect(status).toBe(201);
    expect(data.actionType).toBe(superAdminActionType);
  });

  it("rejects a duplicate actionType", async () => {
    const { status, data } = await apiRequest("/policies", {
      method: "POST",
      token: adminToken,
      body: { actionType, quorumType: "N_OF_M", minApprovals: 1, eligibleRoles: ["ADMIN"] },
    });
    expect(status).toBe(400);
    expect(data.error).toMatch(/already exists/);
  });

  it("updates a policy", async () => {
    const { status, data } = await apiRequest(`/policies/${createdPolicyId}`, {
      method: "PUT",
      token: adminToken,
      body: { minApprovals: 3 },
    });
    expect(status).toBe(200);
    expect(data.minApprovals).toBe(3);
  });

  it("rejects a policy referencing itself as its own fallback", async () => {
    const { status, data } = await apiRequest(`/policies/${createdPolicyId}`, {
      method: "PUT",
      token: adminToken,
      body: { fallbackPolicyId: createdPolicyId },
    });
    expect(status).toBe(400);
    expect(data.error).toMatch(/cannot use itself/);
  });

  it("refuses to delete a policy that an approval request still references", async () => {
    const policy = await apiRequest("/policies", {
      method: "POST",
      token: adminToken,
      body: { actionType: referencedActionType, quorumType: "N_OF_M", minApprovals: 1, eligibleRoles: ["ADMIN"] },
    });
    const policyId = policy.data.id;

    const created = await apiRequest("/actions", {
      method: "POST",
      token: adminToken,
      body: { type: referencedActionType, payload: { amount: 1 } },
    });

    // This is a real bug found via manual testing: deleting a policy with an
    // existing ApprovalRequest used to throw a raw Postgres FK violation
    // (500). The route now checks first and returns a clean 400.
    const del = await apiRequest(`/policies/${policyId}`, { method: "DELETE", token: adminToken });
    expect(del.status).toBe(400);
    expect(del.data.error).toMatch(/still reference it/);

    await prisma.approvalRequest.deleteMany({ where: { policyId } });
    await prisma.sensitiveAction.deleteMany({ where: { id: created.data.action.id } });
    await prisma.approvalPolicy.delete({ where: { id: policyId } });
  });

  it("deletes a policy", async () => {
    const { status, data } = await apiRequest(`/policies/${createdPolicyId}`, {
      method: "DELETE",
      token: adminToken,
    });
    expect(status).toBe(200);
    expect(data.deleted).toBe(true);
  });
});
