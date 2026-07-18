import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  startTestServer,
  stopTestServer,
  apiRequest,
  createUserWithToken,
  addMockPasskey,
  cleanupUsers,
  cleanupPolicies,
  runSuffix,
} from "./testServer.js";
import { prisma } from "../src/lib/prisma.js";

function mockVoteResponse(credentialId: string, signature: string) {
  return {
    id: credentialId,
    response: {
      clientDataJSON: "mock-client-data",
      authenticatorData: "mock-authenticator-data",
      signature,
    },
  };
}

/** Mirrors the real client flow: fetch WebAuthn options first to seed the challenge, then vote. */
async function castVote(requestId: string, voter: { id: string; token: string }, decision: "APPROVE" | "REJECT", signature: string) {
  const options = await apiRequest(`/approvals/${requestId}/options`, { method: "POST", token: voter.token });
  if (options.status !== 200) return options;
  return apiRequest(`/approvals/${requestId}/vote`, {
    method: "POST",
    token: voter.token,
    body: { decision, response: mockVoteResponse(`mock-cred-${voter.id}`, signature) },
  });
}

describe("approval voting and quorum resolution", () => {
  const emails = [
    `vote-creator-${runSuffix}@example.com`,
    `vote-approver1-${runSuffix}@example.com`,
    `vote-approver2-${runSuffix}@example.com`,
    `vote-admin-${runSuffix}@example.com`,
    `vote-senior-${runSuffix}@example.com`,
  ];
  const nOfMType = "test:vote-nofm";
  const roleType = "test:vote-role";

  let creator: { id: string; token: string };
  let approver1: { id: string; token: string };
  let admin: { id: string; token: string };
  let senior: { id: string; token: string };

  beforeAll(async () => {
    await startTestServer();
    await cleanupUsers(emails);
    await cleanupPolicies([nOfMType, roleType]);

    const c = await createUserWithToken({ email: emails[0], role: "MEMBER" });
    const a1 = await createUserWithToken({ email: emails[1], role: "APPROVER" });
    const ad = await createUserWithToken({ email: emails[3], role: "ADMIN" });
    const sr = await createUserWithToken({ email: emails[4], role: "SENIOR_APPROVER" });

    creator = { id: c.user.id, token: c.token };
    approver1 = { id: a1.user.id, token: a1.token };
    admin = { id: ad.user.id, token: ad.token };
    senior = { id: sr.user.id, token: sr.token };

    for (const u of [approver1, admin, senior]) {
      await addMockPasskey(u.id);
    }

    await prisma.approvalPolicy.create({
      data: { actionType: nOfMType, quorumType: "N_OF_M", minApprovals: 2, eligibleRoles: ["APPROVER", "ADMIN"], escalationTimeoutSec: 300 },
    });
    await prisma.approvalPolicy.create({
      data: { actionType: roleType, quorumType: "ROLE_BASED", minApprovals: 1, eligibleRoles: ["ADMIN", "SENIOR_APPROVER"], escalationTimeoutSec: 300 },
    });
  });

  afterAll(async () => {
    // FK-safe order: votes -> requests -> actions -> policies -> users.
    await prisma.approvalVote.deleteMany({ where: { request: { policy: { actionType: { in: [nOfMType, roleType] } } } } });
    await prisma.approvalRequest.deleteMany({ where: { policy: { actionType: { in: [nOfMType, roleType] } } } });
    await prisma.sensitiveAction.deleteMany({ where: { requestedBy: { email: { in: emails } } } });
    await cleanupPolicies([nOfMType, roleType]);
    await cleanupUsers(emails);
    await stopTestServer();
  });

  it("resolves N_OF_M quorum once enough approvals land, and not before", async () => {
    const { data: created } = await apiRequest("/actions", {
      method: "POST",
      token: creator.token,
      body: { type: nOfMType, payload: { amount: 100 } },
    });
    const requestId = created.approvalRequest.id;

    const vote1 = await castVote(requestId, approver1, "APPROVE", "sig-1");
    expect(vote1.status).toBe(200);
    expect(vote1.data.requestStatus).toBe("PENDING");

    const vote2 = await castVote(requestId, admin, "APPROVE", "sig-2");
    expect(vote2.status).toBe(200);
    expect(vote2.data.requestStatus).toBe("APPROVED");

    const dbRequest = await prisma.approvalRequest.findUnique({ where: { id: requestId } });
    const dbAction = await prisma.sensitiveAction.findUnique({ where: { id: created.action.id } });
    expect(dbRequest?.status).toBe("APPROVED");
    expect(dbAction?.status).toBe("APPROVED");
  });

  it("rejects immediately on a single REJECT vote", async () => {
    const { data: created } = await apiRequest("/actions", {
      method: "POST",
      token: creator.token,
      body: { type: nOfMType, payload: { amount: 200 } },
    });
    const requestId = created.approvalRequest.id;

    const vote = await castVote(requestId, approver1, "REJECT", "sig-reject");
    expect(vote.status).toBe(200);
    expect(vote.data.requestStatus).toBe("REJECTED");
  });

  it("rejects a duplicate vote from the same approver", async () => {
    const { data: created } = await apiRequest("/actions", {
      method: "POST",
      token: creator.token,
      body: { type: nOfMType, payload: { amount: 300 } },
    });
    const requestId = created.approvalRequest.id;

    await castVote(requestId, approver1, "APPROVE", "sig-a");
    const dup = await castVote(requestId, approver1, "APPROVE", "sig-b");
    expect(dup.status).toBe(400);
    expect(dup.data.error).toMatch(/already voted/);
  });

  it("blocks the requester from voting on their own action, even when their role is eligible", async () => {
    // admin is both eligible-by-role for nOfMType and the requester here, so a 403
    // can only mean the self-vote check fired (role eligibility alone would pass).
    const { data: created } = await apiRequest("/actions", {
      method: "POST",
      token: admin.token,
      body: { type: nOfMType, payload: { amount: 400 } },
    });
    const requestId = created.approvalRequest.id;

    const vote = await castVote(requestId, admin, "APPROVE", "sig-self");
    expect(vote.status).toBe(403);
  });

  it("blocks an ineligible role from voting", async () => {
    const { data: created } = await apiRequest("/actions", {
      method: "POST",
      token: creator.token,
      body: { type: roleType, payload: { deploy: "prod" } },
    });
    const requestId = created.approvalRequest.id;

    const vote = await castVote(requestId, approver1, "APPROVE", "sig-ineligible");
    expect(vote.status).toBe(403);
  });

  it("resolves ROLE_BASED quorum only once every required role has approved", async () => {
    const { data: created } = await apiRequest("/actions", {
      method: "POST",
      token: creator.token,
      body: { type: roleType, payload: { deploy: "prod" } },
    });
    const requestId = created.approvalRequest.id;

    const first = await castVote(requestId, admin, "APPROVE", "sig-role-1");
    expect(first.data.requestStatus).toBe("PENDING");

    const second = await castVote(requestId, senior, "APPROVE", "sig-role-2");
    expect(second.data.requestStatus).toBe("APPROVED");
  });

  it("excludes requests the user isn't eligible for from /approvals/pending", async () => {
    const { data: created } = await apiRequest("/actions", {
      method: "POST",
      token: creator.token,
      body: { type: roleType, payload: { deploy: "staging" } },
    });

    const pendingForApprover = await apiRequest("/approvals/pending", { token: approver1.token });
    const ids = pendingForApprover.data.map((r: any) => r.id);
    expect(ids).not.toContain(created.approvalRequest.id);

    const pendingForAdmin = await apiRequest("/approvals/pending", { token: admin.token });
    const adminIds = pendingForAdmin.data.map((r: any) => r.id);
    expect(adminIds).toContain(created.approvalRequest.id);
  });
});
