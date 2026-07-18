import { prisma } from "./src/lib/prisma.js";
import { signAccessToken } from "./src/lib/jwt.js";
import crypto from "node:crypto";
import { io } from "socket.io-client";

const API_URL = "http://localhost:4000";

async function runTests() {
  console.log("Setting up test database entries...");

  // 1. Setup multiple users with roles and passkeys
  const emails = {
    creator: "creator@example.com",
    approver1: "approver1@example.com", // role: APPROVER
    approver2: "approver2@example.com", // role: APPROVER
    admin1: "admin1@example.com",       // role: ADMIN
    senior1: "senior1@example.com",     // role: SENIOR_APPROVER
  };

  await prisma.approvalVote.deleteMany({
    where: { approver: { email: { in: Object.values(emails) } } },
  });
  await prisma.approvalVote.deleteMany({
    where: { request: { action: { requestedBy: { email: { in: Object.values(emails) } } } } },
  });
  await prisma.approvalRequest.deleteMany({
    where: { action: { requestedBy: { email: { in: Object.values(emails) } } } },
  });
  await prisma.sensitiveAction.deleteMany({
    where: { requestedBy: { email: { in: Object.values(emails) } } },
  });
  await prisma.credential.deleteMany({
    where: { user: { email: { in: Object.values(emails) } } },
  });
  await prisma.session.deleteMany({
    where: { user: { email: { in: Object.values(emails) } } },
  });
  await prisma.user.deleteMany({
    where: { email: { in: Object.values(emails) } },
  });

  const creatorUser = await prisma.user.create({
    data: { email: emails.creator, name: "Creator", role: "MEMBER" },
  });

  const approver1User = await prisma.user.create({
    data: { email: emails.approver1, name: "Approver One", role: "APPROVER" },
  });

  const approver2User = await prisma.user.create({
    data: { email: emails.approver2, name: "Approver Two", role: "APPROVER" },
  });

  const admin1User = await prisma.user.create({
    data: { email: emails.admin1, name: "Admin One", role: "ADMIN" },
  });

  const senior1User = await prisma.user.create({
    data: { email: emails.senior1, name: "Senior One", role: "SENIOR_APPROVER" },
  });

  // Create passkeys for voters
  const voters = [approver1User, approver2User, admin1User, senior1User];
  for (const voter of voters) {
    await prisma.credential.create({
      data: {
        userId: voter.id,
        type: "PASSKEY",
        credentialId: `cred-${voter.id}`,
        publicKey: "mock-pubkey-data",
        counter: 0,
        deviceLabel: "Test Device",
      },
    });
  }

  // Generate tokens
  const creatorToken = signAccessToken({ sub: creatorUser.id, sessionId: crypto.randomUUID() });
  const app1Token = signAccessToken({ sub: approver1User.id, sessionId: crypto.randomUUID() });
  const app2Token = signAccessToken({ sub: approver2User.id, sessionId: crypto.randomUUID() });
  const adminToken = signAccessToken({ sub: admin1User.id, sessionId: crypto.randomUUID() });
  const seniorToken = signAccessToken({ sub: senior1User.id, sessionId: crypto.randomUUID() });

  console.log("Tokens generated successfully.");

  // Clean up any test policies
  const actionTypeNofM = "test:quorum-nofm";
  const actionTypeRole = "test:quorum-role";

  await prisma.approvalPolicy.deleteMany({
    where: { actionType: { in: [actionTypeNofM, actionTypeRole] } },
  });

  // Create policy 1: N_OF_M (Requires 2 approvals from [APPROVER, ADMIN])
  const policyNofM = await prisma.approvalPolicy.create({
    data: {
      actionType: actionTypeNofM,
      quorumType: "N_OF_M",
      minApprovals: 2,
      eligibleRoles: ["APPROVER", "ADMIN"],
      escalationTimeoutSec: 300,
    },
  });

  // Create policy 2: ROLE_BASED (Requires approvals from ADMIN and SENIOR_APPROVER)
  const policyRole = await prisma.approvalPolicy.create({
    data: {
      actionType: actionTypeRole,
      quorumType: "ROLE_BASED",
      minApprovals: 1, // minApprovals ignored for role-based
      eligibleRoles: ["ADMIN", "SENIOR_APPROVER"],
      escalationTimeoutSec: 300,
    },
  });

  // Helper request function
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

  console.log("\n--- Starting Voting Engine Integration Tests ---\n");

  // Create two sensitive actions to be approved
  // Action 1: N_OF_M
  const { data: act1Data } = await request("/actions", "POST", creatorToken, {
    type: actionTypeNofM,
    payload: { amount: 1000 },
  });
  const reqNofMId = act1Data.approvalRequest.id;
  const actNofMId = act1Data.action.id;

  // Action 2: ROLE_BASED
  const { data: act2Data } = await request("/actions", "POST", creatorToken, {
    type: actionTypeRole,
    payload: { repo: "nova-forge", branch: "main" },
  });
  const reqRoleId = act2Data.approvalRequest.id;
  const actRoleId = act2Data.action.id;

  // Test 1: GET /approvals/pending for App1 (APPROVER) -> should show reqNofMId, NOT reqRoleId (eligible role mismatch)
  {
    const { status, data } = await request("/approvals/pending", "GET", app1Token);
    console.log(`Test 1 (Pending approvals listing): Status ${status}, found:`, data.map((r: any) => r.id));
    if (status !== 200) throw new Error("Test 1 failed");
    const ids = data.map((r: any) => r.id);
    if (!ids.includes(reqNofMId)) throw new Error("Missing eligible request");
    if (ids.includes(reqRoleId)) throw new Error("Should not show ineligible request");
  }

  // Test 2: GET /approvals/pending for Senior1 (SENIOR_APPROVER) -> should show reqRoleId, NOT reqNofMId
  {
    const { status, data } = await request("/approvals/pending", "GET", seniorToken);
    console.log(`Test 2 (Pending approvals for Senior): Status ${status}, found:`, data.map((r: any) => r.id));
    if (status !== 200) throw new Error("Test 2 failed");
    const ids = data.map((r: any) => r.id);
    if (!ids.includes(reqRoleId)) throw new Error("Missing eligible request");
    if (ids.includes(reqNofMId)) throw new Error("Should not show ineligible request");
  }

  // Set up socket listener for live events
  console.log("Setting up Socket.io client listener...");
  const socket = io(API_URL, { forceNew: true });
  let socketVoteCastEvent: any = null;
  let socketStatusUpdateEvent: any = null;

  socket.on("connect", () => {
    socket.emit("join-challenge", reqNofMId);
  });

  socket.on("vote-cast", (event) => {
    console.log("Socket Event: vote-cast received:", event);
    socketVoteCastEvent = event;
  });

  socket.on("status-update", (event) => {
    console.log("Socket Event: status-update received:", event);
    socketStatusUpdateEvent = event;
  });

  // Give socket connection a tiny bit of time
  await new Promise((r) => setTimeout(r, 500));

  // Test 3: POST /approvals/:id/options -> get WebAuthn challenge options
  let app1Challenge = "";
  {
    const { status, data } = await request(`/approvals/${reqNofMId}/options`, "POST", app1Token);
    console.log(`Test 3 (Fetch challenge options): Status ${status}, challenge:`, data.challenge);
    if (status !== 200 || !data.challenge) throw new Error("Test 3 failed");
    app1Challenge = data.challenge;
  }

  // Test 4: POST /approvals/:id/vote -> submit vote 1 (APPROVE)
  {
    const voteBody = {
      decision: "APPROVE",
      response: {
        id: `cred-${approver1User.id}`,
        response: {
          clientDataJSON: "mock-client-data",
          authenticatorData: "mock-authenticator-data",
          signature: "mock-sig-1",
        },
      },
    };
    const { status, data } = await request(`/approvals/${reqNofMId}/vote`, "POST", app1Token, voteBody);
    console.log(`Test 4 (Submit Vote 1): Status ${status}`, data);
    if (status !== 200 || data.requestStatus !== "PENDING" || !data.verified) {
      throw new Error("Test 4 failed");
    }

    // Verify database record
    const voteRecord = await prisma.approvalVote.findFirst({
      where: { requestId: reqNofMId, approverId: approver1User.id },
    });
    if (!voteRecord || voteRecord.signature !== "mock-sig-1") {
      throw new Error("Vote not written to database correctly");
    }

    // Verify audit log has VOTE_CAST entry
    const voteAudit = await prisma.auditLog.findFirst({
      where: { entityType: "ApprovalVote", entityId: voteRecord.id, event: "VOTE_CAST" },
    });
    if (!voteAudit) throw new Error("Vote audit log missing");
    console.log("Database & Audit Log for Vote 1 verified successfully.");

    // Check socket vote cast event
    await new Promise((r) => setTimeout(r, 200));
    if (!socketVoteCastEvent || socketVoteCastEvent.decision !== "APPROVE") {
      throw new Error("Socket vote-cast event not emitted correctly");
    }
    console.log("Socket event verified successfully.");
  }

  // Test 5: Re-voting should fail (duplicate check)
  {
    const voteBody = {
      decision: "APPROVE",
      response: {
        id: `cred-${approver1User.id}`,
        response: { signature: "mock-sig-dup" },
      },
    };
    const { status, data } = await request(`/approvals/${reqNofMId}/vote`, "POST", app1Token, voteBody);
    console.log(`Test 5 (Duplicate vote protection): Status ${status}`, data);
    if (status !== 400 || !data.error.includes("already voted")) throw new Error("Test 5 failed");
  }

  // Test 6: POST /approvals/:id/options -> get options for Admin1
  {
    const { status, data } = await request(`/approvals/${reqNofMId}/options`, "POST", adminToken);
    if (status !== 200) throw new Error("Test 6 options failed");
  }

  // Test 7: POST /approvals/:id/vote -> submit vote 2 (APPROVE) -> N_OF_M Quorum reached!
  {
    const voteBody = {
      decision: "APPROVE",
      response: {
        id: `cred-${admin1User.id}`,
        response: { signature: "mock-sig-2" },
      },
    };
    const { status, data } = await request(`/approvals/${reqNofMId}/vote`, "POST", adminToken, voteBody);
    console.log(`Test 7 (Submit Vote 2 - Quorum reach): Status ${status}`, data);
    if (status !== 200 || data.requestStatus !== "APPROVED") {
      throw new Error("Test 7 failed");
    }

    // Verify DB update
    const updatedRequest = await prisma.approvalRequest.findUnique({ where: { id: reqNofMId } });
    const updatedAction = await prisma.sensitiveAction.findUnique({ where: { id: actNofMId } });
    if (updatedRequest?.status !== "APPROVED" || updatedAction?.status !== "APPROVED") {
      throw new Error("Request or Action status not updated in DB");
    }

    // Verify audit logs
    const requestAudit = await prisma.auditLog.findFirst({
      where: { entityType: "ApprovalRequest", entityId: reqNofMId, event: "REQUEST_APPROVED" },
    });
    const actionAudit = await prisma.auditLog.findFirst({
      where: { entityType: "SensitiveAction", entityId: actNofMId, event: "ACTION_APPROVED" },
    });
    if (!requestAudit || !actionAudit) throw new Error("Quorum audit logs missing");
    console.log("Database & Audit Log for Quorum achieved verified successfully.");

    // Check socket status update event
    await new Promise((r) => setTimeout(r, 200));
    if (!socketStatusUpdateEvent || socketStatusUpdateEvent.status !== "APPROVED") {
      throw new Error("Socket status-update event not emitted correctly");
    }
    console.log("Socket status-update event verified successfully.");
  }

  // Test 8: Test ROLE_BASED policy voting and resolution
  {
    // Submit Admin1 approval
    await request(`/approvals/${reqRoleId}/options`, "POST", adminToken);
    await request(`/approvals/${reqRoleId}/vote`, "POST", adminToken, {
      decision: "APPROVE",
      response: { id: `cred-${admin1User.id}`, response: { signature: "mock-sig-r1" } },
    });

    // Request is still PENDING because we also need SENIOR_APPROVER
    const midReq = await prisma.approvalRequest.findUnique({ where: { id: reqRoleId } });
    console.log(`Test 8 (Role-based middle status):`, midReq?.status);
    if (midReq?.status !== "PENDING") throw new Error("Role-based policy resolved too early");

    // Submit Senior1 approval
    await request(`/approvals/${reqRoleId}/options`, "POST", seniorToken);
    const { data: finalData } = await request(`/approvals/${reqRoleId}/vote`, "POST", seniorToken, {
      decision: "APPROVE",
      response: { id: `cred-${senior1User.id}`, response: { signature: "mock-sig-r2" } },
    });
    console.log(`Test 8 (Role-based final status):`, finalData.requestStatus);
    if (finalData.requestStatus !== "APPROVED") throw new Error("Role-based policy failed to resolve");
  }

  // Test 9: Test rejection flow (1 reject -> reject)
  // Create another action
  const { data: act3Data } = await request("/actions", "POST", creatorToken, {
    type: actionTypeNofM,
    payload: { amount: 5000 },
  });
  const reqRejectId = act3Data.approvalRequest.id;
  const actRejectId = act3Data.action.id;

  {
    await request(`/approvals/${reqRejectId}/options`, "POST", app1Token);
    const { data } = await request(`/approvals/${reqRejectId}/vote`, "POST", app1Token, {
      decision: "REJECT",
      response: { id: `cred-${approver1User.id}`, response: { signature: "mock-sig-reject" } },
    });
    console.log(`Test 9 (Rejection flow status):`, data.requestStatus);
    if (data.requestStatus !== "REJECTED") throw new Error("Rejection flow failed");

    // Verify DB update
    const dbReq = await prisma.approvalRequest.findUnique({ where: { id: reqRejectId } });
    const dbAct = await prisma.sensitiveAction.findUnique({ where: { id: actRejectId } });
    if (dbReq?.status !== "REJECTED" || dbAct?.status !== "REJECTED") {
      throw new Error("DB state for rejection mismatch");
    }

    // Verify audit logs
    const rejectAudit = await prisma.auditLog.findFirst({
      where: { entityType: "ApprovalRequest", entityId: reqRejectId, event: "REQUEST_REJECTED" },
    });
    if (!rejectAudit) throw new Error("Rejection audit log missing");
    console.log("Database & Audit Log for rejection verified successfully.");
  }

  // Close socket client
  socket.close();

  // Clean up
  console.log("\n--- Cleaning up test database entries... ---");
  await prisma.approvalVote.deleteMany({
    where: { requestId: { in: [reqNofMId, reqRoleId, reqRejectId] } },
  });
  await prisma.approvalRequest.deleteMany({
    where: { id: { in: [reqNofMId, reqRoleId, reqRejectId] } },
  });
  await prisma.sensitiveAction.deleteMany({
    where: { id: { in: [actNofMId, actRoleId, actRejectId] } },
  });
  await prisma.approvalPolicy.deleteMany({
    where: { id: { in: [policyNofM.id, policyRole.id] } },
  });
  await prisma.credential.deleteMany({
    where: { userId: { in: [creatorUser.id, approver1User.id, approver2User.id, admin1User.id, senior1User.id] } },
  });
  await prisma.session.deleteMany({
    where: { userId: { in: [creatorUser.id, approver1User.id, approver2User.id, admin1User.id, senior1User.id] } },
  });
  await prisma.user.deleteMany({
    where: { email: { in: Object.values(emails) } },
  });

  console.log("All tests passed successfully!");
}

runTests().catch((e) => {
  console.error("Test execution failed:", e);
  process.exit(1);
});
