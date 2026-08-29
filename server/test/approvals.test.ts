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
import { Prisma } from "@prisma/client";

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

  // Regression coverage for P0-1: ApprovalVote.requestId+approverId used to be
  // deduplicated only by an application-level findFirst-then-create check,
  // which is a classic TOCTOU race -- two concurrent requests can both pass
  // the findFirst before either commits. This test bypasses the HTTP route
  // entirely and fires two real, concurrent INSERTs at Postgres for the exact
  // same (requestId, approverId) pair via Promise.all, proving the database's
  // own UNIQUE(requestId, approverId) constraint -- not the application check
  // -- is what makes duplication impossible. Using Promise.all (not two
  // sequential awaits) is what actually exercises the race window: both
  // inserts are in flight against Postgres at the same time.
  it("the database allows only one of two genuinely concurrent inserts for the same (requestId, approverId)", async () => {
    const { data: created } = await apiRequest("/actions", {
      method: "POST",
      token: creator.token,
      body: { type: nOfMType, payload: { amount: 350 } },
    });
    const requestId = created.approvalRequest.id;

    const insertVote = (signature: string) =>
      prisma.approvalVote.create({
        data: {
          requestId,
          approverId: approver1.id,
          decision: "APPROVE",
          signature,
          deviceId: `mock-cred-${approver1.id}`,
        },
      });

    const results = await Promise.allSettled([insertVote("sig-race-1"), insertVote("sig-race-2")]);

    const fulfilled = results.filter((r) => r.status === "fulfilled");
    const rejected = results.filter((r) => r.status === "rejected");
    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);

    const rejection = (rejected[0] as PromiseRejectedResult).reason;
    expect(rejection).toBeInstanceOf(Prisma.PrismaClientKnownRequestError);
    expect((rejection as Prisma.PrismaClientKnownRequestError).code).toBe("P2002");

    const votes = await prisma.approvalVote.findMany({ where: { requestId, approverId: approver1.id } });
    expect(votes).toHaveLength(1);
  });

  // Same regression, exercised through the real HTTP route with genuinely
  // concurrent requests (Promise.all, not sequential awaits). Unlike the
  // direct-Prisma test above, the exact status code the "losing" request gets
  // back is legitimately timing-dependent here: the single-use WebAuthn
  // challenge store (server/src/lib/challengeStore.ts) is keyed per
  // approver+request and deletes-on-read, so depending on interleaving the
  // second request may lose at the challenge-consumption step (400, "session
  // expired") rather than at the duplicate-vote step -- both are legitimate,
  // safe outcomes. What must hold deterministically, and is what this test
  // asserts, is the end-to-end invariant: never two 200s, never a 500, and
  // never more than one ApprovalVote row persisted for the pair.
  it("handles two genuinely concurrent HTTP vote submissions from the same approver without a 500 or a duplicate row", async () => {
    const { data: created } = await apiRequest("/actions", {
      method: "POST",
      token: creator.token,
      body: { type: nOfMType, payload: { amount: 360 } },
    });
    const requestId = created.approvalRequest.id;

    const [first, second] = await Promise.all([
      castVote(requestId, approver1, "APPROVE", "sig-concurrent-1"),
      castVote(requestId, approver1, "APPROVE", "sig-concurrent-2"),
    ]);

    const statuses = [first.status, second.status].sort();
    expect(statuses).not.toContain(500);
    expect(statuses.filter((s) => s === 200)).toHaveLength(1);
    expect(statuses.filter((s) => s === 400)).toHaveLength(1);

    const votes = await prisma.approvalVote.findMany({ where: { requestId, approverId: approver1.id } });
    expect(votes).toHaveLength(1);
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
