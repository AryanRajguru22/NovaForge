import { prisma } from "./src/lib/prisma.js";
import { signAccessToken } from "./src/lib/jwt.js";
import crypto from "node:crypto";

const API_URL = "http://localhost:4000/policies";

async function runTests() {
  console.log("Setting up test database entries...");

  // 1. Setup Admin and Member users
  const adminEmail = "test-admin@example.com";
  const memberEmail = "test-member@example.com";

  await prisma.user.deleteMany({
    where: { email: { in: [adminEmail, memberEmail] } },
  });

  const admin = await prisma.user.create({
    data: {
      email: adminEmail,
      name: "Test Admin",
      role: "ADMIN",
    },
  });

  const member = await prisma.user.create({
    data: {
      email: memberEmail,
      name: "Test Member",
      role: "MEMBER",
    },
  });

  // Generate tokens
  const adminToken = signAccessToken({ sub: admin.id, sessionId: crypto.randomUUID() });
  const memberToken = signAccessToken({ sub: member.id, sessionId: crypto.randomUUID() });

  let testPolicyId = "";

  console.log("\n--- Starting CRUD Integration Tests ---\n");

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

  // Test 1: GET /policies without auth -> should return 401
  {
    const { status, data } = await request("/", "GET");
    console.log(`Test 1 (GET without auth): Status ${status}`, data);
    if (status !== 401) throw new Error("Test 1 failed");
  }

  // Test 2: GET /policies with member auth -> should return 200 (any list)
  {
    const { status, data } = await request("/", "GET", memberToken);
    console.log(`Test 2 (GET with member auth): Status ${status}, array check:`, Array.isArray(data));
    if (status !== 200 || !Array.isArray(data)) throw new Error("Test 2 failed");
  }

  // Test 3: POST /policies with member auth -> should return 403 (Forbidden)
  {
    const { status, data } = await request("/", "POST", memberToken, {
      actionType: "test:sensitive-deploy",
      quorumType: "N_OF_M",
      minApprovals: 2,
      eligibleRoles: ["ADMIN", "SENIOR_APPROVER"],
    });
    console.log(`Test 3 (POST with member auth): Status ${status}`, data);
    if (status !== 403) throw new Error("Test 3 failed");
  }

  // Test 4: POST /policies with admin auth -> should create policy (201)
  {
    const { status, data } = await request("/", "POST", adminToken, {
      actionType: "test:sensitive-deploy",
      quorumType: "N_OF_M",
      minApprovals: 2,
      eligibleRoles: ["ADMIN", "SENIOR_APPROVER"],
      escalationTimeoutSec: 150,
    });
    console.log(`Test 4 (POST with admin auth): Status ${status}`, data);
    if (status !== 201 || !data.id) throw new Error("Test 4 failed");
    testPolicyId = data.id;
  }

  // Test 5: POST /policies with duplicate actionType -> should return 400
  {
    const { status, data } = await request("/", "POST", adminToken, {
      actionType: "test:sensitive-deploy",
      quorumType: "N_OF_M",
      minApprovals: 1,
      eligibleRoles: ["ADMIN"],
    });
    console.log(`Test 5 (POST duplicate actionType): Status ${status}`, data);
    if (status !== 400) throw new Error("Test 5 failed");
  }

  // Test 6: GET /policies/:id with member auth -> should return 200
  {
    const { status, data } = await request(`/${testPolicyId}`, "GET", memberToken);
    console.log(`Test 6 (GET policy by ID): Status ${status}`, data);
    if (status !== 200 || data.id !== testPolicyId) throw new Error("Test 6 failed");
  }

  // Test 7: PUT /policies/:id with member auth -> should return 403
  {
    const { status, data } = await request(`/${testPolicyId}`, "PUT", memberToken, {
      minApprovals: 3,
    });
    console.log(`Test 7 (PUT with member auth): Status ${status}`, data);
    if (status !== 403) throw new Error("Test 7 failed");
  }

  // Test 8: PUT /policies/:id with admin auth -> should update (200)
  {
    const { status, data } = await request(`/${testPolicyId}`, "PUT", adminToken, {
      minApprovals: 3,
      escalationTimeoutSec: 120,
    });
    console.log(`Test 8 (PUT with admin auth): Status ${status}`, data);
    if (status !== 200 || data.minApprovals !== 3 || data.escalationTimeoutSec !== 120) throw new Error("Test 8 failed");
  }

  // Test 9: DELETE /policies/:id with member auth -> should return 403
  {
    const { status, data } = await request(`/${testPolicyId}`, "DELETE", memberToken);
    console.log(`Test 9 (DELETE with member auth): Status ${status}`, data);
    if (status !== 403) throw new Error("Test 9 failed");
  }

  // Test 10: DELETE /policies/:id with admin auth -> should delete (200)
  {
    const { status, data } = await request(`/${testPolicyId}`, "DELETE", adminToken);
    console.log(`Test 10 (DELETE with admin auth): Status ${status}`, data);
    if (status !== 200 || !data.deleted) throw new Error("Test 10 failed");
  }

  // Test 11: GET /policies/:id -> should return 404
  {
    const { status, data } = await request(`/${testPolicyId}`, "GET", memberToken);
    console.log(`Test 11 (GET deleted policy): Status ${status}`, data);
    if (status !== 404) throw new Error("Test 11 failed");
  }

  console.log("\n--- Cleaning up test database entries... ---");
  await prisma.user.deleteMany({
    where: { email: { in: [adminEmail, memberEmail] } },
  });

  console.log("All tests passed successfully!");
}

runTests().catch((e) => {
  console.error("Test execution failed:", e);
  process.exit(1);
});
