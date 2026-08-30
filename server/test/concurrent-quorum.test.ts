import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { io as ioClient, type Socket } from "socket.io-client";
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

// P0-2 regression coverage: server/src/routes/approvals.ts previously
// recalculated quorum from an unlocked findMany and wrote the resulting
// status with a plain, unconditional update. Under READ COMMITTED (Postgres's
// default, never overridden anywhere in this codebase), two concurrent vote
// transactions for the SAME request could each see only their own
// just-inserted vote -- the other's insert, still uncommitted, is invisible
// to a concurrent transaction's read -- so both could independently compute
// an incomplete tally, and an unconditional write could blindly overwrite
// whatever another such transaction had just committed. The fix locks the
// specific ApprovalRequest row (SELECT ... FOR UPDATE) as the first
// operation in the transaction and makes every status transition a
// conditional (WHERE status = 'PENDING') compare-and-swap. Every test below
// fires genuinely concurrent HTTP requests via Promise.all -- never two
// sequential awaits -- specifically to exercise that lock/race window.

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

async function castVote(requestId: string, voter: { id: string; token: string }, decision: "APPROVE" | "REJECT", signature: string) {
  const options = await apiRequest(`/approvals/${requestId}/options`, { method: "POST", token: voter.token });
  if (options.status !== 200) return options;
  return apiRequest(`/approvals/${requestId}/vote`, {
    method: "POST",
    token: voter.token,
    body: { decision, response: mockVoteResponse(`mock-cred-${voter.id}`, signature) },
  });
}

async function auditCount(entityType: string, entityId: string, event: string) {
  return prisma.auditLog.count({ where: { entityType, entityId, event } });
}

describe("P0-2: concurrent quorum resolution", () => {
  const emails = [
    `cq-creator-${runSuffix}@example.com`,
    `cq-approver-a-${runSuffix}@example.com`,
    `cq-approver-b-${runSuffix}@example.com`,
    `cq-approver-c-${runSuffix}@example.com`,
    `cq-role-admin-${runSuffix}@example.com`,
    `cq-role-senior-${runSuffix}@example.com`,
  ];
  const nOfMType = "test:cq-nofm";
  const roleType = "test:cq-role";

  let creator: { id: string; token: string };
  let approverA: { id: string; token: string };
  let approverB: { id: string; token: string };
  let approverC: { id: string; token: string };
  let roleAdmin: { id: string; token: string };
  let roleSenior: { id: string; token: string };
  let baseUrl = "";

  beforeAll(async () => {
    baseUrl = await startTestServer();
    await cleanupUsers(emails);
    await cleanupPolicies([nOfMType, roleType]);

    const c = await createUserWithToken({ email: emails[0], role: "MEMBER" });
    const a = await createUserWithToken({ email: emails[1], role: "APPROVER" });
    const b = await createUserWithToken({ email: emails[2], role: "APPROVER" });
    const cc = await createUserWithToken({ email: emails[3], role: "APPROVER" });
    const ra = await createUserWithToken({ email: emails[4], role: "ADMIN" });
    const rs = await createUserWithToken({ email: emails[5], role: "SENIOR_APPROVER" });

    creator = { id: c.user.id, token: c.token };
    approverA = { id: a.user.id, token: a.token };
    approverB = { id: b.user.id, token: b.token };
    approverC = { id: cc.user.id, token: cc.token };
    roleAdmin = { id: ra.user.id, token: ra.token };
    roleSenior = { id: rs.user.id, token: rs.token };

    for (const u of [approverA, approverB, approverC, roleAdmin, roleSenior]) {
      await addMockPasskey(u.id);
    }

    await prisma.approvalPolicy.create({
      data: { actionType: nOfMType, quorumType: "N_OF_M", minApprovals: 2, eligibleRoles: ["APPROVER"], escalationTimeoutSec: 300 },
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

  async function createRequest(actionType: string, amount: number) {
    const { data } = await apiRequest("/actions", {
      method: "POST",
      token: creator.token,
      body: { type: actionType, payload: { amount } },
    });
    return data;
  }

  it("TEST 1: two concurrent APPROVE votes, neither alone sufficient, together reach N_OF_M quorum", async () => {
    const created = await createRequest(nOfMType, 1);
    const requestId = created.approvalRequest.id;

    // Whichever transaction wins the row-lock race sees only its own
    // just-inserted vote (1 < minApprovals=2) and stays PENDING without
    // writing anything -- which is exactly what leaves the row PENDING for
    // the second transaction to legitimately proceed and see both votes.
    // Both votes are therefore always accepted here, regardless of ordering.
    const [r1, r2] = await Promise.all([
      castVote(requestId, approverA, "APPROVE", "t1-sig-a"),
      castVote(requestId, approverB, "APPROVE", "t1-sig-b"),
    ]);

    expect(r1.status).toBe(200);
    expect(r2.status).toBe(200);
    const statuses = [r1.data.requestStatus, r2.data.requestStatus].sort();
    expect(statuses).toEqual(["APPROVED", "PENDING"]);

    const dbRequest = await prisma.approvalRequest.findUnique({ where: { id: requestId } });
    const dbAction = await prisma.sensitiveAction.findUnique({ where: { id: created.action.id } });
    expect(dbRequest?.status).toBe("APPROVED");
    expect(dbAction?.status).toBe("APPROVED");

    const votes = await prisma.approvalVote.findMany({ where: { requestId } });
    expect(votes).toHaveLength(2);

    expect(await auditCount("ApprovalRequest", requestId, "REQUEST_APPROVED")).toBe(1);
    expect(await auditCount("SensitiveAction", created.action.id, "ACTION_APPROVED")).toBe(1);
  });

  // Real socket.io-client check (server/package.json already carries this as
  // a devDependency for the app's own real-time client -- no new dependency
  // added here): proves the transitionWon gate on the terminal status-update
  // emission (server/src/routes/approvals.ts) actually results in exactly
  // one event reaching a connected client, not just that the gating code
  // exists. The socket joins the request's room and starts collecting events
  // *before* either vote fires, so there's no race between "join" and
  // "emit": both concurrent votes are only sent after the join is
  // acknowledged over the socket connection.
  it("TEST 1b: concurrent APPROVE votes that resolve quorum emit exactly one terminal status-update event over Socket.io", async () => {
    const created = await createRequest(nOfMType, 101);
    const requestId = created.approvalRequest.id;

    const socket: Socket = ioClient(baseUrl, { transports: ["websocket"], forceNew: true });
    const statusUpdates: Array<{ requestId: string; status: string }> = [];
    socket.on("status-update", (payload: { requestId: string; status: string }) => {
      if (payload.requestId === requestId) statusUpdates.push(payload);
    });

    // join-challenge has no server-side ack (server/src/app.ts's handler is
    // fire-and-forget: socket.on("join-challenge", (id) => socket.join(id))),
    // so there's no confirmation to wait on beyond the connection itself
    // being fully established. socket.emit here is sent over an already-live
    // connection the instant "connect" fires, and the server's join
    // processing (a synchronous socket.join() call, no I/O) completes long
    // before either vote's HTTP round trip -- which involves real DB
    // work -- reaches the point of emitting anything.
    await new Promise<void>((resolve, reject) => {
      socket.on("connect_error", reject);
      socket.on("connect", () => {
        socket.emit("join-challenge", requestId);
        resolve();
      });
    });

    try {
      const [r1, r2] = await Promise.all([
        castVote(requestId, approverA, "APPROVE", "t1b-sig-a"),
        castVote(requestId, approverB, "APPROVE", "t1b-sig-b"),
      ]);
      expect(r1.status).toBe(200);
      expect(r2.status).toBe(200);

      // The terminal emit happens synchronously in the same request handler
      // that already returned above, before the HTTP response is sent --
      // this wait is a generous delivery buffer over a loopback socket, not
      // a race against a deadline for correctness.
      await new Promise((resolve) => setTimeout(resolve, 500));

      expect(statusUpdates).toHaveLength(1);
      expect(statusUpdates[0]?.status).toBe("APPROVED");
    } finally {
      socket.disconnect();
    }
  });

  it("TEST 2: concurrent APPROVE + REJECT never lets the request end up APPROVED, regardless of which transaction wins the row lock", async () => {
    const created = await createRequest(nOfMType, 2);
    const requestId = created.approvalRequest.id;

    // Deliberately no prior vote exists on this request: with minApprovals=2
    // a single concurrent APPROVE vote can never independently resolve the
    // request by itself. Two orderings are both legitimate here, and this
    // test was originally written asserting only the first of them, which a
    // real concurrent run disproved (documented in the P0-2 final
    // verification report, not weakened away here):
    //  - REJECT wins the lock race first: it's an unconditional, immediate
    //    veto the moment it's visible in a tally, so it resolves the
    //    request to REJECTED by itself; APPROVE then arrives at an
    //    already-non-PENDING row and is cleanly bounced with 400.
    //  - APPROVE wins the lock race first: alone it can never satisfy
    //    minApprovals=2, so it succeeds (200) but leaves the request
    //    PENDING without writing anything; REJECT then arrives while the
    //    row is still legitimately PENDING, also succeeds (200), and
    //    resolves the request to REJECTED once it sees both votes.
    // Both orderings are correct, and BOTH deterministically end with the
    // database at REJECTED, never APPROVED, and neither response ever
    // reports the request as APPROVED -- that is the actual, provable
    // invariant, not a specific HTTP-status-code pattern.
    const [rApprove, rReject] = await Promise.all([
      castVote(requestId, approverA, "APPROVE", "t2-sig-approve"),
      castVote(requestId, approverB, "REJECT", "t2-sig-reject"),
    ]);

    expect(rApprove.status).not.toBe(500);
    expect(rReject.status).not.toBe(500);
    if (rApprove.status === 200) {
      expect(rApprove.data.requestStatus).not.toBe("APPROVED");
    }
    if (rReject.status === 200) {
      expect(rReject.data.requestStatus).toBe("REJECTED");
    }

    const dbRequest = await prisma.approvalRequest.findUnique({ where: { id: requestId } });
    const dbAction = await prisma.sensitiveAction.findUnique({ where: { id: created.action.id } });
    expect(dbRequest?.status).toBe("REJECTED");
    expect(dbAction?.status).toBe("REJECTED");

    expect(await auditCount("ApprovalRequest", requestId, "REQUEST_APPROVED")).toBe(0);
    expect(await auditCount("ApprovalRequest", requestId, "REQUEST_REJECTED")).toBe(1);
    expect(await auditCount("SensitiveAction", created.action.id, "ACTION_APPROVED")).toBe(0);
    expect(await auditCount("SensitiveAction", created.action.id, "ACTION_REJECTED")).toBe(1);
  });

  it("TEST 3: two concurrent REJECT votes resolve to exactly one terminal transition, with no duplicate audit rows", async () => {
    const created = await createRequest(nOfMType, 3);
    const requestId = created.approvalRequest.id;

    const [r1, r2] = await Promise.all([
      castVote(requestId, approverA, "REJECT", "t3-sig-a"),
      castVote(requestId, approverB, "REJECT", "t3-sig-b"),
    ]);

    // A REJECT vote is an unconditional, immediate veto -- whichever of the
    // two acquires the row lock first resolves the request to REJECTED by
    // itself. Because this implementation refuses to insert a vote against a
    // request that its own locked, in-transaction re-check finds is no
    // longer PENDING, the second REJECT never gets inserted at all once the
    // first has already committed -- it is cleanly bounced with the same
    // "no longer pending" response any vote arriving after a decision is
    // final gets. That is deliberately correct for an approval system: once
    // a decision is final, a second, later vote doesn't get to also "count"
    // -- which is exactly what eliminates the duplicate REQUEST_REJECTED /
    // ACTION_REJECTED audit rows this test proves are gone.
    const statuses = [r1.status, r2.status].sort();
    expect(statuses).not.toContain(500);
    expect(statuses.filter((s) => s === 200)).toHaveLength(1);
    expect(statuses.filter((s) => s === 400)).toHaveLength(1);

    const dbRequest = await prisma.approvalRequest.findUnique({ where: { id: requestId } });
    const dbAction = await prisma.sensitiveAction.findUnique({ where: { id: created.action.id } });
    expect(dbRequest?.status).toBe("REJECTED");
    expect(dbAction?.status).toBe("REJECTED");

    const votes = await prisma.approvalVote.findMany({ where: { requestId } });
    expect(votes).toHaveLength(1);

    expect(await auditCount("ApprovalRequest", requestId, "REQUEST_REJECTED")).toBe(1);
    expect(await auditCount("SensitiveAction", created.action.id, "ACTION_REJECTED")).toBe(1);
  });

  it("TEST 5: two concurrent APPROVE votes from different required roles, neither alone sufficient, together satisfy ROLE_BASED quorum", async () => {
    const created = await createRequest(roleType, 5);
    const requestId = created.approvalRequest.id;

    const [r1, r2] = await Promise.all([
      castVote(requestId, roleAdmin, "APPROVE", "t5-sig-admin"),
      castVote(requestId, roleSenior, "APPROVE", "t5-sig-senior"),
    ]);

    expect(r1.status).toBe(200);
    expect(r2.status).toBe(200);
    const statuses = [r1.data.requestStatus, r2.data.requestStatus].sort();
    expect(statuses).toEqual(["APPROVED", "PENDING"]);

    const dbRequest = await prisma.approvalRequest.findUnique({ where: { id: requestId } });
    expect(dbRequest?.status).toBe("APPROVED");

    const votes = await prisma.approvalVote.findMany({ where: { requestId } });
    expect(votes).toHaveLength(2);

    expect(await auditCount("ApprovalRequest", requestId, "REQUEST_APPROVED")).toBe(1);
    expect(await auditCount("SensitiveAction", created.action.id, "ACTION_APPROVED")).toBe(1);
  });

  it("TEST 6: a third concurrent APPROVE arriving once quorum is already met cannot mutate an already-terminal request", async () => {
    const created = await createRequest(nOfMType, 6);
    const requestId = created.approvalRequest.id;

    // All three eligible approvers fire concurrently. minApprovals=2, so
    // whichever two transactions the row lock happens to serialize first
    // resolve the request to APPROVED; the third -- whichever one that ends
    // up being -- necessarily finds the request already non-PENDING once it
    // finally acquires the lock, and its vote is never inserted at all. The
    // specific identity of "which two win" is not deterministic, but the
    // *pattern* (exactly 2 votes land, exactly 1 terminal transition,
    // exactly 1 late arrival cleanly bounced, APPROVED never flips to
    // anything else) is -- that pattern is what this test asserts.
    const results = await Promise.all([
      castVote(requestId, approverA, "APPROVE", "t6-sig-a"),
      castVote(requestId, approverB, "APPROVE", "t6-sig-b"),
      castVote(requestId, approverC, "APPROVE", "t6-sig-c"),
    ]);

    const statuses = results.map((r) => r.status).sort();
    expect(statuses).not.toContain(500);
    expect(statuses.filter((s) => s === 400)).toHaveLength(1);
    expect(statuses.filter((s) => s === 200)).toHaveLength(2);

    const dbRequest = await prisma.approvalRequest.findUnique({ where: { id: requestId } });
    const dbAction = await prisma.sensitiveAction.findUnique({ where: { id: created.action.id } });
    expect(dbRequest?.status).toBe("APPROVED");
    expect(dbAction?.status).toBe("APPROVED");

    const votes = await prisma.approvalVote.findMany({ where: { requestId } });
    expect(votes).toHaveLength(2);

    expect(await auditCount("ApprovalRequest", requestId, "REQUEST_APPROVED")).toBe(1);
    expect(await auditCount("SensitiveAction", created.action.id, "ACTION_APPROVED")).toBe(1);
  });
});
