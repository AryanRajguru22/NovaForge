import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { startTestServer, stopTestServer, apiRequest, createUserWithToken, cleanupUsers, cleanupPolicies, runSuffix } from "./testServer.js";

describe("policy management", () => {
  const emails = [`policy-admin-${runSuffix}@example.com`, `policy-member-${runSuffix}@example.com`];
  const actionType = "test:policy-crud";
  let adminToken: string;
  let memberToken: string;
  let createdPolicyId: string;

  beforeAll(async () => {
    await startTestServer();
    await cleanupUsers(emails);
    await cleanupPolicies([actionType]);
    adminToken = (await createUserWithToken({ email: emails[0], role: "ADMIN" })).token;
    memberToken = (await createUserWithToken({ email: emails[1], role: "MEMBER" })).token;
  });

  afterAll(async () => {
    await cleanupPolicies([actionType]);
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

  it("deletes a policy", async () => {
    const { status, data } = await apiRequest(`/policies/${createdPolicyId}`, {
      method: "DELETE",
      token: adminToken,
    });
    expect(status).toBe(200);
    expect(data.deleted).toBe(true);
  });
});
