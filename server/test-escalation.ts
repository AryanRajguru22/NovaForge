import { prisma } from "./src/lib/prisma.js";
import { signAccessToken } from "./src/lib/jwt.js";
import crypto from "node:crypto";
import { io } from "socket.io-client";

const API_URL = "http://localhost:4000";

async function runTests() {
  console.log("Setting up test database entries for escalation...");

  const emails = {
    creator: "esc-creator@example.com",
    approver1: "esc-approver@example.com",
    admin1: "esc-admin@example.com",
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
    data: { email: emails.creator, name: "Esc Creator", role: "MEMBER" },
  });

  const approverUser = await prisma.user.create({
    data: { email: emails.approver1, name: "Esc Approver", role: "APPROVER" },
  });

  const adminUser = await prisma.user.create({
    data: { email: emails.admin1, name: "Esc Admin", role: "ADMIN" },
  });

  // Create passkeys
  await prisma.credential.create({
    data: {
      userId: approverUser.id,
      type: "PASSKEY",
      credentialId: `cred-${approverUser.id}`,
      publicKey: "mock-pubkey",
      deviceLabel: "Test Device",
    },
  });

  // Generate tokens
  const creatorToken = signAccessToken({ sub: creatorUser.id, sessionId: crypto.randomUUID() });
  const approverToken = signAccessToken({ sub: approverUser.id, sessionId: crypto.randomUUID() });

  const primaryActionType = "test:primary-policy";
  const fallbackActionType = "test:fallback-policy";
  const noFallbackActionType = "test:no-fallback-policy";

  // Clean up policies
  await prisma.approvalPolicy.deleteMany({
    where: { actionType: { in: [primaryActionType, fallbackActionType, noFallbackActionType] } },
  });

  // 1. Create Fallback Policy
  const fallbackPolicy = await prisma.approvalPolicy.create({
    data: {
      actionType: fallbackActionType,
      quorumType: "N_OF_M",
      minApprovals: 1,
      eligibleRoles: ["ADMIN"],
      escalationTimeoutSec: 300,
    },
  });

  // 2. Create Primary Policy (timeout: 2 seconds)
  const primaryPolicy = await prisma.approvalPolicy.create({
    data: {
      actionType: primaryActionType,
      quorumType: "N_OF_M",
      minApprovals: 2,
      eligibleRoles: ["APPROVER"],
      escalationTimeoutSec: 2, // 2 seconds timeout for fast escalation
      fallbackPolicyId: fallbackPolicy.id,
    },
  });

  // 3. Create Policy with no fallback (timeout: 2 seconds)
  const noFallbackPolicy = await prisma.approvalPolicy.create({
    data: {
      actionType: noFallbackActionType,
      quorumType: "N_OF_M",
      minApprovals: 1,
      eligibleRoles: ["APPROVER"],
      escalationTimeoutSec: 2, // 2 seconds timeout for fast expiration
      fallbackPolicyId: null,
    },
  });

  console.log("Policies created successfully.");

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

  console.log("\n--- Creating actions for escalation test ---\n");

  // Create action 1: Primary policy (will escalate)
  const { data: act1Data } = await request("/actions", "POST", creatorToken, {
    type: primaryActionType,
    payload: { action: "deploy-critical" },
  });
  const reqEscId = act1Data.approvalRequest.id;
  const actEscId = act1Data.action.id;

  // Create action 2: No-fallback policy (will expire)
  const { data: act2Data } = await request("/actions", "POST", creatorToken, {
    type: noFallbackActionType,
    payload: { action: "unapproved-config" },
  });
  const reqExpId = act2Data.approvalRequest.id;
  const actExpId = act2Data.action.id;

  console.log(`Action 1 created with ApprovalRequest ID: ${reqEscId}`);
  console.log(`Action 2 created with ApprovalRequest ID: ${reqExpId}`);

  // Cast a vote on Action 1 before it escalates to verify votes are preserved!
  await request(`/approvals/${reqEscId}/options`, "POST", approverToken);
  await request(`/approvals/${reqEscId}/vote`, "POST", approverToken, {
    decision: "APPROVE",
    response: {
      id: `cred-${approverUser.id}`,
      response: { signature: "mock-sig-pre-esc" },
    },
  });

  console.log("Cast pre-escalation approval vote.");

  // Set up socket listeners for both request IDs
  const socket1 = io(API_URL, { forceNew: true });
  const socket2 = io(API_URL, { forceNew: true });
  let socketEscalatedEvent: any = null;
  let socketExpiredEvent: any = null;

  socket1.on("connect", () => socket1.emit("join-challenge", reqEscId));
  socket2.on("connect", () => socket2.emit("join-challenge", reqExpId));

  socket1.on("escalated", (event) => {
    console.log("Socket Event: escalated received:", event);
    socketEscalatedEvent = event;
  });

  socket2.on("status-update", (event) => {
    console.log("Socket Event: status-update received:", event);
    socketExpiredEvent = event;
  });

  console.log("Waiting 7 seconds for timeouts and escalation daemon to run...");
  await new Promise((r) => setTimeout(r, 7000));

  console.log("\n--- Verification stage ---\n");

  // Verify Action 1 (escalated)
  const dbReqEsc = await prisma.approvalRequest.findUnique({
    where: { id: reqEscId },
    include: { votes: true },
  });
  const dbActEsc = await prisma.sensitiveAction.findUnique({
    where: { id: actEscId },
  });

  console.log("Escalated request status in DB:", dbReqEsc?.status);
  console.log("Escalated request current policyId:", dbReqEsc?.policyId);
  console.log("Preserved votes count:", dbReqEsc?.votes.length);

  if (dbReqEsc?.policyId !== fallbackPolicy.id) throw new Error("Request did not escalate to fallback policy");
  if (dbReqEsc?.status !== "PENDING") throw new Error("Request status should remain PENDING");
  if (dbReqEsc?.votes.length !== 1) throw new Error("Votes were not preserved during escalation");

  // Verify audit logs for escalation
  const escTrigAudit = await prisma.auditLog.findFirst({
    where: { entityType: "ApprovalRequest", entityId: reqEscId, event: "ESCALATION_TRIGGERED" },
  });
  const fallbackAssignAudit = await prisma.auditLog.findFirst({
    where: { entityType: "ApprovalRequest", entityId: reqEscId, event: "FALLBACK_POLICY_ASSIGNED" },
  });
  if (!escTrigAudit || !fallbackAssignAudit) throw new Error("Escalation audit logs missing");
  console.log("Audit log verification passed for escalation.");

  // Verify Socket.io event for escalation
  if (!socketEscalatedEvent || socketEscalatedEvent.newPolicyId !== fallbackPolicy.id) {
    throw new Error("Socket.io escalated event not received or invalid");
  }
  console.log("Socket.io verification passed for escalation.");

  // Verify Action 2 (expired)
  const dbReqExp = await prisma.approvalRequest.findUnique({
    where: { id: reqExpId },
  });
  const dbActExp = await prisma.sensitiveAction.findUnique({
    where: { id: actExpId },
  });

  console.log("Expired request status in DB:", dbReqExp?.status);
  console.log("Expired action status in DB:", dbActExp?.status);

  if (dbReqExp?.status !== "EXPIRED" || dbActExp?.status !== "EXPIRED") {
    throw new Error("No-fallback request did not transition to EXPIRED");
  }

  // Verify audit logs for expiration
  const expReqAudit = await prisma.auditLog.findFirst({
    where: { entityType: "ApprovalRequest", entityId: reqExpId, event: "REQUEST_EXPIRED" },
  });
  const expActAudit = await prisma.auditLog.findFirst({
    where: { entityType: "SensitiveAction", entityId: actExpId, event: "ACTION_EXPIRED" },
  });
  if (!expReqAudit || !expActAudit) throw new Error("Expiration audit logs missing");
  console.log("Audit log verification passed for expiration.");

  // Verify Socket.io event for expiration
  if (!socketExpiredEvent || socketExpiredEvent.status !== "EXPIRED") {
    throw new Error("Socket.io expired status-update event not received or invalid");
  }
  console.log("Socket.io verification passed for expiration.");

  socket1.close();
  socket2.close();

  // Clean up
  console.log("\n--- Cleaning up test database entries... ---");
  await prisma.approvalVote.deleteMany({
    where: { requestId: { in: [reqEscId, reqExpId] } },
  });
  await prisma.approvalRequest.deleteMany({
    where: { id: { in: [reqEscId, reqExpId] } },
  });
  await prisma.sensitiveAction.deleteMany({
    where: { id: { in: [actEscId, actExpId] } },
  });
  await prisma.approvalPolicy.deleteMany({
    where: { id: { in: [primaryPolicy.id, fallbackPolicy.id, noFallbackPolicy.id] } },
  });
  await prisma.credential.deleteMany({
    where: { userId: { in: [creatorUser.id, approverUser.id, adminUser.id] } },
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
