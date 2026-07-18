import { prisma } from "./src/lib/prisma.js";
import { signAccessToken } from "./src/lib/jwt.js";
import crypto from "node:crypto";

const API_URL = "http://localhost:4000";

async function runTests() {
  console.log("Setting up test database entries...");

  // 1. Setup Admin and Member users
  const adminEmail = "actions-admin@example.com";
  const memberEmail = "actions-member@example.com";

  await prisma.user.deleteMany({
    where: { email: { in: [adminEmail, memberEmail] } },
  });

  const admin = await prisma.user.create({
    data: {
      email: adminEmail,
      name: "Actions Test Admin",
      role: "ADMIN",
    },
  });

  const member = await prisma.user.create({
    data: {
      email: memberEmail,
      name: "Actions Test Member",
      role: "MEMBER",
    },
  });

  // Generate tokens
  const adminToken = signAccessToken({ sub: admin.id, sessionId: crypto.randomUUID() });
  const memberToken = signAccessToken({ sub: member.id, sessionId: crypto.randomUUID() });

  // Delete any existing policies for our test action types
  const actionTypeWithPolicy = "test:deploy-app";
  const actionTypeWithoutPolicy = "test:no-policy-app";

  await prisma.approvalPolicy.deleteMany({
    where: { actionType: { in: [actionTypeWithPolicy, actionTypeWithoutPolicy] } },
  });

  // Create a policy for one action type
  const policy = await prisma.approvalPolicy.create({
    data: {
      actionType: actionTypeWithPolicy,
      quorumType: "N_OF_M",
      minApprovals: 2,
      eligibleRoles: ["ADMIN", "SENIOR_APPROVER"],
      escalationTimeoutSec: 150,
    },
  });

  console.log("\n--- Starting Sensitive Actions Integration Tests ---\n");

  // Helper to make requests with cookies
  const request = async (path: string, method: string, token?: string, body?: object) => {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (token) {
      headers["Cookie"] = `accessToken=${token}`;
    }
    const response = await fetch(`${API_URL}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });
    const status = response.status;
    let data;
    try {
      data = await response.json();
    } catch {
      data = null;
    }
    return { status, data };
  };

  let createdActionId = "";

  // Test 1: POST /actions without auth -> should return 401
  {
    const { status, data } = await request("/actions", "POST");
    console.log(`Test 1 (POST without auth): Status ${status}`, data);
    if (status !== 401) throw new Error("Test 1 failed");
  }

  // Test 2: POST /actions with type that has no policy configured -> should return 400
  {
    const { status, data } = await request("/actions", "POST", memberToken, {
      type: actionTypeWithoutPolicy,
      payload: { target: "production", version: "v1.0.0" },
    });
    console.log(`Test 2 (POST type with no policy): Status ${status}`, data);
    if (status !== 400 || !data.error.includes("No approval policy configured")) {
      throw new Error("Test 2 failed");
    }
  }

  // Test 3: POST /actions with invalid payload structure (e.g. missing payload) -> should return 400
  {
    const { status, data } = await request("/actions", "POST", memberToken, {
      type: actionTypeWithPolicy,
    });
    console.log(`Test 3 (POST missing payload): Status ${status}`, data);
    if (status !== 400 || !data.error.includes("Invalid request data")) {
      throw new Error("Test 3 failed");
    }
  }

  // Test 4: POST /actions with valid data -> should return 201 and create the Action & ApprovalRequest
  {
    const { status, data } = await request("/actions", "POST", memberToken, {
      type: actionTypeWithPolicy,
      payload: { cluster: "k8s-prod", cpuLimit: "4" },
    });
    console.log(`Test 4 (POST valid action creation): Status ${status}`, data);
    if (status !== 201 || !data.action.id || !data.approvalRequest.id) {
      throw new Error("Test 4 failed");
    }
    createdActionId = data.action.id;

    // Database verification: Check that records are created correctly in DB
    const dbAction = await prisma.sensitiveAction.findUnique({
      where: { id: createdActionId },
      include: { approvalRequest: true },
    });
    if (!dbAction || dbAction.type !== actionTypeWithPolicy) {
      throw new Error("Action not created correctly in DB");
    }
    if (!dbAction.approvalRequest || dbAction.approvalRequest.policyId !== policy.id) {
      throw new Error("ApprovalRequest not created or linked correctly in DB");
    }
    console.log("Database verification: SensitiveAction & ApprovalRequest verified successfully in DB.");

    // Audit verification: Check audit log contains ACTION_CREATED entry
    const auditLogs = await prisma.auditLog.findMany({
      where: { entityType: "SensitiveAction", entityId: createdActionId, event: "ACTION_CREATED" },
    });
    if (auditLogs.length !== 1 || auditLogs[0].actorId !== member.id) {
      throw new Error("Audit log not written correctly");
    }
    console.log("Audit verification: AuditLog entry verified successfully in DB.");
  }

  // Test 5: GET /actions/:id without auth -> should return 401
  {
    const { status, data } = await request(`/actions/${createdActionId}`, "GET");
    console.log(`Test 5 (GET without auth): Status ${status}`, data);
    if (status !== 401) throw new Error("Test 5 failed");
  }

  // Test 6: GET /actions/:id with non-existent ID -> should return 404
  {
    const nonExistentId = crypto.randomUUID();
    const { status, data } = await request(`/actions/${nonExistentId}`, "GET", memberToken);
    console.log(`Test 6 (GET non-existent ID): Status ${status}`, data);
    if (status !== 404) throw new Error("Test 6 failed");
  }

  // Test 7: GET /actions/:id with valid ID -> should return details, policy, and empty votes array
  {
    const { status, data } = await request(`/actions/${createdActionId}`, "GET", memberToken);
    console.log(`Test 7 (GET action details): Status ${status}`);
    if (status !== 200) throw new Error("Test 7 failed");
    if (data.action.id !== createdActionId) throw new Error("Action ID mismatch");
    if (data.action.requestedBy.email !== memberEmail) throw new Error("RequestedBy user mismatch");
    if (data.approvalRequest.policy.id !== policy.id) throw new Error("ApprovalRequest policy mismatch");
    if (!Array.isArray(data.approvalRequest.votes) || data.approvalRequest.votes.length !== 0) {
      throw new Error("Votes array mismatch");
    }
  }

  // Clean up
  console.log("\n--- Cleaning up test database entries... ---");
  await prisma.approvalRequest.deleteMany({
    where: { actionId: createdActionId },
  });
  await prisma.sensitiveAction.deleteMany({
    where: { id: createdActionId },
  });
  await prisma.approvalPolicy.deleteMany({
    where: { id: policy.id },
  });
  await prisma.user.deleteMany({
    where: { email: { in: [adminEmail, memberEmail] } },
  });

  console.log("All tests passed successfully!");
}

runTests().catch((e) => {
  console.error("Test execution failed:", e);
  process.exit(1);
});
