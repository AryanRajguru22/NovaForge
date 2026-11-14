import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  startTestServer,
  stopTestServer,
  apiRequest,
  createUserWithToken,
  addMockPasskey,
  governanceProof,
  cleanupUsers,
  cleanupPolicies,
  runSuffix,
} from "./testServer.js";
import { prisma } from "../src/lib/prisma.js";

// Every policy mutation requires a fresh passkey proof (Phase 1), so each call
// below fetches one for its actor exactly as the real client does.
describe("policy management", () => {
  const emails = [
    `policy-admin-${runSuffix}@example.com`,
    `policy-member-${runSuffix}@example.com`,
    `policy-superadmin-${runSuffix}@example.com`,
  ];
  const actionType = "test:policy-crud";
  const referencedActionType = "test:policy-delete-referenced";
  const superAdminActionType = "test:policy-superadmin-crud";
  let admin: { id: string; token: string };
  let memberToken: string;
  let superAdmin: { id: string; token: string };
  let createdPolicyId: string;

  const proof = (actor: { id: string; token: string }) => governanceProof(actor, "policy");

  beforeAll(async () => {
    await startTestServer();
    await cleanupUsers(emails);
    await cleanupPolicies([actionType, referencedActionType, superAdminActionType]);
    const a = await createUserWithToken({ email: emails[0], role: "ADMIN" });
    admin = { id: a.user.id, token: a.token };
    await addMockPasskey(admin.id);
    memberToken = (await createUserWithToken({ email: emails[1], role: "MEMBER" })).token;
    const s = await createUserWithToken({ email: emails[2], role: "SUPER_ADMIN" });
    superAdmin = { id: s.user.id, token: s.token };
    await addMockPasskey(superAdmin.id);
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
      token: admin.token,
      body: { actionType, quorumType: "N_OF_M", minApprovals: 2, eligibleRoles: ["ADMIN"], response: await proof(admin) },
    });
    expect(status).toBe(201);
    expect(data.actionType).toBe(actionType);
    createdPolicyId = data.id;
  });

  it("lets a super admin do everything an admin can, including creating a policy", async () => {
    const { status, data } = await apiRequest("/policies", {
      method: "POST",
      token: superAdmin.token,
      body: {
        actionType: superAdminActionType,
        quorumType: "N_OF_M",
        minApprovals: 1,
        eligibleRoles: ["ADMIN"],
        response: await proof(superAdmin),
      },
    });
    expect(status).toBe(201);
    expect(data.actionType).toBe(superAdminActionType);
  });

  it("rejects a duplicate actionType", async () => {
    const { status, data } = await apiRequest("/policies", {
      method: "POST",
      token: admin.token,
      body: { actionType, quorumType: "N_OF_M", minApprovals: 1, eligibleRoles: ["ADMIN"], response: await proof(admin) },
    });
    expect(status).toBe(400);
    expect(data.error).toMatch(/already exists/);
  });

  it("updates a policy", async () => {
    const { status, data } = await apiRequest(`/policies/${createdPolicyId}`, {
      method: "PUT",
      token: admin.token,
      body: { minApprovals: 3, response: await proof(admin) },
    });
    expect(status).toBe(200);
    expect(data.minApprovals).toBe(3);
  });

  it("rejects a policy referencing itself as its own fallback", async () => {
    const { status, data } = await apiRequest(`/policies/${createdPolicyId}`, {
      method: "PUT",
      token: admin.token,
      body: { fallbackPolicyId: createdPolicyId, response: await proof(admin) },
    });
    expect(status).toBe(400);
    expect(data.error).toMatch(/cannot use itself/);
  });

  it("refuses to delete a policy that an approval request still references", async () => {
    const policy = await apiRequest("/policies", {
      method: "POST",
      token: admin.token,
      body: { actionType: referencedActionType, quorumType: "N_OF_M", minApprovals: 1, eligibleRoles: ["ADMIN"], response: await proof(admin) },
    });
    const policyId = policy.data.id;

    const created = await apiRequest("/actions", {
      method: "POST",
      token: admin.token,
      body: { type: referencedActionType, payload: { amount: 1 } },
    });

    // This is a real bug found via manual testing: deleting a policy with an
    // existing ApprovalRequest used to throw a raw Postgres FK violation
    // (500). The route now checks first and returns a clean 400.
    const del = await apiRequest(`/policies/${policyId}`, { method: "DELETE", token: admin.token, body: { response: await proof(admin) } });
    expect(del.status).toBe(400);
    expect(del.data.error).toMatch(/still reference it/);

    await prisma.approvalRequest.deleteMany({ where: { policyId } });
    await prisma.sensitiveAction.deleteMany({ where: { id: created.data.action.id } });
    await prisma.approvalPolicy.delete({ where: { id: policyId } });
  });

  it("deletes a policy", async () => {
    const { status, data } = await apiRequest(`/policies/${createdPolicyId}`, {
      method: "DELETE",
      token: admin.token,
      body: { response: await proof(admin) },
    });
    expect(status).toBe(200);
    expect(data.deleted).toBe(true);
  });
});
