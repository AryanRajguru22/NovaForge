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
  castVote as castSignedVote,
} from "./testServer.js";
import { prisma } from "../src/lib/prisma.js";
import { signAccessToken } from "../src/lib/jwt.js";

// P0-3 regression coverage: server/src/lib/socketSecurity.ts. Before this,
// server/src/app.ts accepted every Socket.io connection unconditionally and
// let it join any room -- keyed by ApprovalRequest.id -- by name alone, with
// no authentication or authorization at all. These tests exercise the real
// security boundary end-to-end against a real Socket.io server and real
// Postgres:
//
//   cookie -> JWT -> live Session -> authenticated socket
//     -> fresh request/policy lookup -> requester OR eligible role -> room
//
// A short sweep interval is used file-wide (not the 60s production default)
// specifically so TEST 13 can wait for a real "disconnect" event rather than
// a fixed sleep -- see startTestServer below.

type JoinAck = { ok: true } | { ok: false; error: string };

function connectSocket(baseUrl: string, token: string | undefined): Socket {
  const headers: Record<string, string> = {};
  if (token) headers.Cookie = `accessToken=${token}`;
  // Node's socket.io-client (unlike a browser) honors extraHeaders on the
  // handshake request, including for a websocket-only connection -- the
  // standard way for a Node-based test client to present the same cookie a
  // real browser sends automatically via withCredentials: true.
  // reconnection is disabled throughout this file: these tests assert on
  // the *first* connect/connect_error outcome deterministically, and a
  // background reconnection loop retrying after an intentional rejection
  // would just be test noise (and a leaked timer) to clean up afterward.
  return ioClient(baseUrl, {
    transports: ["websocket"],
    forceNew: true,
    reconnection: false,
    extraHeaders: headers,
  });
}

function waitForConnect(socket: Socket): Promise<void> {
  return new Promise((resolve, reject) => {
    socket.once("connect", () => resolve());
    socket.once("connect_error", (err) => reject(err));
  });
}

function waitForConnectError(socket: Socket): Promise<Error> {
  return new Promise((resolve, reject) => {
    socket.once("connect", () => reject(new Error("expected connect_error but the socket connected")));
    socket.once("connect_error", (err: Error) => resolve(err));
  });
}

function joinRequest(socket: Socket, requestId: string): Promise<JoinAck> {
  return new Promise((resolve) => {
    socket.emit("join-challenge", requestId, (result: JoinAck) => resolve(result));
  });
}

// The trailing "signature" argument is kept only so existing call sites read
// unchanged; the real signature is produced by the voter's software
// authenticator over the server's decision-bound challenge.
async function castVote(requestId: string, voter: { id: string; token: string }, decision: "APPROVE" | "REJECT", _signature?: string) {
  return castSignedVote(requestId, voter, decision);
}

describe("P0-3: Socket.io authentication and authorization", () => {
  const emails = [
    `sock-requester-${runSuffix}@example.com`,
    `sock-eligible-${runSuffix}@example.com`,
    `sock-ineligible-${runSuffix}@example.com`,
    `sock-unrelated-${runSuffix}@example.com`,
    `sock-revoke-new-${runSuffix}@example.com`,
    `sock-revoke-existing-${runSuffix}@example.com`,
    `sock-rolechange-${runSuffix}@example.com`,
  ];
  const nOfMType = `test:socket-security-nofm-${runSuffix}`;
  const singleVoteType = `test:socket-security-single-${runSuffix}`;
  const policyChangeType = `test:socket-security-policychange-${runSuffix}`;
  const requesterSurvivesType = `test:socket-security-requester-survives-${runSuffix}`;
  const policyChangeFallbackType = `test:socket-security-policychange-fallback-${runSuffix}`;
  const allActionTypes = [nOfMType, singleVoteType, policyChangeType, requesterSurvivesType, policyChangeFallbackType];

  let baseUrl = "";
  let requesterUser: { id: string; token: string };
  let eligibleApprover: { id: string; token: string };
  let ineligibleApprover: { id: string; token: string };
  let unrelatedMember: { id: string; token: string };

  beforeAll(async () => {
    // A short sweep interval (not the 60s production default) is passed
    // here specifically so TEST 13 can observe a real revocation sweep
    // within a normal test timeout -- every other test in this file
    // completes in well under this interval, so it doesn't otherwise affect
    // them (a live session is confirmed live and left alone either way).
    baseUrl = await startTestServer({ sweepIntervalMs: 300 });
    await cleanupUsers(emails);
    await cleanupPolicies(allActionTypes);

    const requester = await createUserWithToken({ email: emails[0], role: "MEMBER" });
    const eligible = await createUserWithToken({ email: emails[1], role: "APPROVER" });
    const ineligible = await createUserWithToken({ email: emails[2], role: "SENIOR_APPROVER" });
    const unrelated = await createUserWithToken({ email: emails[3], role: "MEMBER" });

    requesterUser = { id: requester.user.id, token: requester.token };
    eligibleApprover = { id: eligible.user.id, token: eligible.token };
    ineligibleApprover = { id: ineligible.user.id, token: ineligible.token };
    unrelatedMember = { id: unrelated.user.id, token: unrelated.token };

    await addMockPasskey(eligibleApprover.id);

    await prisma.approvalPolicy.create({
      data: { actionType: nOfMType, quorumType: "N_OF_M", minApprovals: 2, eligibleRoles: ["APPROVER"], escalationTimeoutSec: 300 },
    });
    await prisma.approvalPolicy.create({
      data: { actionType: singleVoteType, quorumType: "N_OF_M", minApprovals: 1, eligibleRoles: ["APPROVER"], escalationTimeoutSec: 300 },
    });
  });

  afterAll(async () => {
    await prisma.approvalVote.deleteMany({ where: { request: { policy: { actionType: { in: allActionTypes } } } } });
    await prisma.approvalRequest.deleteMany({ where: { policy: { actionType: { in: allActionTypes } } } });
    await prisma.sensitiveAction.deleteMany({ where: { type: { in: allActionTypes } } });
    await cleanupPolicies(allActionTypes);
    await cleanupUsers(emails);
    await stopTestServer();
  });

  async function createRequest(token: string, actionType: string, amount: number) {
    const { data } = await apiRequest("/actions", {
      method: "POST",
      token,
      body: { type: actionType, payload: { amount } },
    });
    return data;
  }

  it("TEST 1: an unauthenticated connection (no cookie at all) is denied", async () => {
    const socket = connectSocket(baseUrl, undefined);
    try {
      const err = await waitForConnectError(socket);
      expect(err).toBeInstanceOf(Error);
      expect(socket.connected).toBe(false);
    } finally {
      socket.disconnect();
    }
  });

  it("TEST 2: an invalid access token is denied", async () => {
    const socket = connectSocket(baseUrl, "not-a-real-jwt");
    try {
      await waitForConnectError(socket);
      expect(socket.connected).toBe(false);
    } finally {
      socket.disconnect();
    }
  });

  it("TEST 3: a cryptographically valid JWT naming a missing or expired session is denied", async () => {
    // Missing session: a well-formed, correctly-signed token, but the
    // sessionId it names was never a real Session row.
    const missingSessionToken = signAccessToken({
      sub: requesterUser.id,
      sessionId: "00000000-0000-4000-8000-000000000000",
    });
    const socket1 = connectSocket(baseUrl, missingSessionToken);
    try {
      await waitForConnectError(socket1);
      expect(socket1.connected).toBe(false);
    } finally {
      socket1.disconnect();
    }

    // Expired session: a real Session row, but its expiresAt has already
    // passed -- JWT validity alone must never be treated as sufficient.
    const expiredSession = await prisma.session.create({
      data: { userId: requesterUser.id, deviceId: "expired-device", expiresAt: new Date(Date.now() - 1000) },
    });
    const expiredToken = signAccessToken({ sub: requesterUser.id, sessionId: expiredSession.id });
    const socket2 = connectSocket(baseUrl, expiredToken);
    try {
      await waitForConnectError(socket2);
      expect(socket2.connected).toBe(false);
    } finally {
      socket2.disconnect();
      await prisma.session.deleteMany({ where: { id: expiredSession.id } });
    }
  });

  it("TEST 4: a valid, live session is accepted", async () => {
    const socket = connectSocket(baseUrl, requesterUser.token);
    try {
      await waitForConnect(socket);
      expect(socket.connected).toBe(true);
    } finally {
      socket.disconnect();
    }
  });

  it("TEST 5: the requester can join their own request's room", async () => {
    const created = await createRequest(requesterUser.token, nOfMType, 5);
    const socket = connectSocket(baseUrl, requesterUser.token);
    try {
      await waitForConnect(socket);
      const result = await joinRequest(socket, created.approvalRequest.id);
      expect(result).toEqual({ ok: true });
    } finally {
      socket.disconnect();
    }
  });

  it("TEST 6: an eligible approver can join", async () => {
    const created = await createRequest(requesterUser.token, nOfMType, 6);
    const socket = connectSocket(baseUrl, eligibleApprover.token);
    try {
      await waitForConnect(socket);
      const result = await joinRequest(socket, created.approvalRequest.id);
      expect(result).toEqual({ ok: true });
    } finally {
      socket.disconnect();
    }
  });

  it("TEST 7: an unrelated MEMBER is denied and receives no events for the request", async () => {
    const created = await createRequest(requesterUser.token, nOfMType, 7);
    const requestId = created.approvalRequest.id;
    const socket = connectSocket(baseUrl, unrelatedMember.token);
    try {
      await waitForConnect(socket);
      const events: unknown[] = [];
      socket.on("vote-cast", (payload) => events.push(payload));
      socket.on("status-update", (payload) => events.push(payload));

      const result = await joinRequest(socket, requestId);
      expect(result.ok).toBe(false);

      // Prove there's genuinely no room membership, not just that the ack
      // said no: a real vote on this request must reach zero events here.
      const vote = await castVote(requestId, eligibleApprover, "APPROVE", "t7-sig");
      expect(vote.status).toBe(200);
      await new Promise((resolve) => setTimeout(resolve, 300));
      expect(events).toHaveLength(0);
    } finally {
      socket.disconnect();
    }
  });

  it("TEST 8: an approver whose role is not in this policy's eligibleRoles is denied", async () => {
    const created = await createRequest(requesterUser.token, nOfMType, 8);
    const socket = connectSocket(baseUrl, ineligibleApprover.token);
    try {
      await waitForConnect(socket);
      const result = await joinRequest(socket, created.approvalRequest.id);
      expect(result.ok).toBe(false);
    } finally {
      socket.disconnect();
    }
  });

  // The central security property: knowledge of a real, valid request UUID
  // is never, by itself, sufficient -- not even combined with a fully valid,
  // live, authenticated session. This is exactly the "leaked link" scenario:
  // an attacker with a real id and their own legitimate (but unrelated)
  // account still gets nothing.
  it("TEST 9 (security): valid UUID + valid session + no legitimate relationship = denied", async () => {
    const created = await createRequest(requesterUser.token, nOfMType, 9);
    const requestId = created.approvalRequest.id;

    const socket = connectSocket(baseUrl, unrelatedMember.token);
    try {
      await waitForConnect(socket);
      expect(socket.connected).toBe(true); // authentication succeeds...
      const result = await joinRequest(socket, requestId);
      expect(result).toEqual({ ok: false, error: "Not authorized" }); // ...authorization still doesn't.
    } finally {
      socket.disconnect();
    }
  });

  it("TEST 10: a random, well-formed but nonexistent UUID is denied", async () => {
    const socket = connectSocket(baseUrl, requesterUser.token);
    try {
      await waitForConnect(socket);
      const result = await joinRequest(socket, "00000000-0000-4000-8000-000000000001");
      expect(result.ok).toBe(false);
    } finally {
      socket.disconnect();
    }
  });

  it("TEST 11: cross-request room isolation -- a socket never receives another request's events", async () => {
    const createdA = await createRequest(requesterUser.token, singleVoteType, 111);
    const createdB = await createRequest(requesterUser.token, singleVoteType, 112);
    const requestIdA = createdA.approvalRequest.id;
    const requestIdB = createdB.approvalRequest.id;

    // Two independent connections as the same eligible approver -- Socket.io
    // rooms are per-connection, not per-user, so this legitimately tests two
    // separate sockets each joined to a different room.
    const socket1 = connectSocket(baseUrl, eligibleApprover.token);
    const socket2 = connectSocket(baseUrl, eligibleApprover.token);
    try {
      await Promise.all([waitForConnect(socket1), waitForConnect(socket2)]);

      const eventsOn1: Array<{ requestId: string }> = [];
      const eventsOn2: Array<{ requestId: string }> = [];
      socket1.on("vote-cast", (p: { requestId: string }) => eventsOn1.push(p));
      socket2.on("vote-cast", (p: { requestId: string }) => eventsOn2.push(p));

      const [join1, join2] = await Promise.all([joinRequest(socket1, requestIdA), joinRequest(socket2, requestIdB)]);
      expect(join1).toEqual({ ok: true });
      expect(join2).toEqual({ ok: true });

      // Real production events via the real REST vote route, not synthetic
      // ones -- minApprovals=1 means each vote alone resolves its request.
      const voteA = await castVote(requestIdA, eligibleApprover, "APPROVE", "t11-sig-a");
      const voteB = await castVote(requestIdB, eligibleApprover, "APPROVE", "t11-sig-b");
      expect(voteA.status).toBe(200);
      expect(voteB.status).toBe(200);
      await new Promise((resolve) => setTimeout(resolve, 300));

      expect(eventsOn1.map((e) => e.requestId)).toEqual([requestIdA]);
      expect(eventsOn2.map((e) => e.requestId)).toEqual([requestIdB]);
    } finally {
      socket1.disconnect();
      socket2.disconnect();
    }
  });

  it("TEST 12: a revoked session cannot be used to establish a new socket connection", async () => {
    const created = await createUserWithToken({ email: emails[4], role: "MEMBER" });
    const payload = JSON.parse(Buffer.from(created.token.split(".")[1], "base64url").toString());

    const socketBefore = connectSocket(baseUrl, created.token);
    try {
      await waitForConnect(socketBefore);
      expect(socketBefore.connected).toBe(true);
    } finally {
      socketBefore.disconnect();
    }

    await prisma.session.delete({ where: { id: payload.sessionId } });

    const socketAfter = connectSocket(baseUrl, created.token);
    try {
      await waitForConnectError(socketAfter);
      expect(socketAfter.connected).toBe(false);
    } finally {
      socketAfter.disconnect();
    }
  });

  it(
    "TEST 13: an already-connected, already-joined socket is disconnected by the periodic sweep after its session is revoked",
    async () => {
      const created = await createUserWithToken({ email: emails[5], role: "APPROVER" });
      const payload = JSON.parse(Buffer.from(created.token.split(".")[1], "base64url").toString());
      const request = await createRequest(requesterUser.token, nOfMType, 13);

      const socket = connectSocket(baseUrl, created.token);
      const disconnected = new Promise<void>((resolve) => socket.once("disconnect", () => resolve()));
      try {
        await waitForConnect(socket);
        const join = await joinRequest(socket, request.approvalRequest.id);
        expect(join).toEqual({ ok: true });

        await prisma.session.delete({ where: { id: payload.sessionId } });

        // Deterministic: waits for the real "disconnect" event the sweep
        // causes, not a fixed sleep guessing when the sweep has run. Bounded
        // by this file's own short sweep interval (beforeAll), well inside
        // this test's own timeout.
        await disconnected;
        expect(socket.connected).toBe(false);
      } finally {
        socket.disconnect();
      }
    },
    10_000,
  );

  it("TEST 14: a role change is reflected on the very next join, not the stale connection-time role", async () => {
    const created = await createUserWithToken({ email: emails[6], role: "APPROVER" });
    const request = await createRequest(requesterUser.token, nOfMType, 14);

    const socket = connectSocket(baseUrl, created.token);
    try {
      await waitForConnect(socket);
      const firstJoin = await joinRequest(socket, request.approvalRequest.id);
      expect(firstJoin).toEqual({ ok: true }); // eligible while role is APPROVER

      await prisma.user.update({ where: { id: created.user.id }, data: { role: "SENIOR_APPROVER" } });

      // Same socket, same request, re-emitted -- if the authorization check
      // used the handshake-time socket.data.role snapshot instead of a
      // fresh User read, this would incorrectly still succeed.
      const secondJoin = await joinRequest(socket, request.approvalRequest.id);
      expect(secondJoin.ok).toBe(false);
    } finally {
      socket.disconnect();
    }
  });

  // Phase 1: a request's rules are an immutable snapshot, so editing the LIVE
  // policy no longer changes who may watch an existing request. What can
  // change eligibility mid-life is escalation to the next pre-captured level;
  // that is reflected on the very next join, as the live-policy edit used to be.
  it("TEST 15: an escalation to a level with different eligibleRoles is reflected on the very next join; editing the live policy is not", async () => {
    const fallback = await prisma.approvalPolicy.create({
      data: { actionType: policyChangeFallbackType, quorumType: "N_OF_M", minApprovals: 1, eligibleRoles: ["SENIOR_APPROVER"], escalationTimeoutSec: 300 },
    });
    const policy = await prisma.approvalPolicy.create({
      data: {
        actionType: policyChangeType,
        quorumType: "N_OF_M",
        minApprovals: 1,
        eligibleRoles: ["APPROVER"],
        escalationTimeoutSec: 300,
        fallbackPolicyId: fallback.id,
      },
    });
    const request = await createRequest(requesterUser.token, policyChangeType, 15);
    const requestId = request.approvalRequest.id;

    const socket = connectSocket(baseUrl, eligibleApprover.token);
    try {
      await waitForConnect(socket);
      const before = await joinRequest(socket, requestId);
      expect(before).toEqual({ ok: true });

      // Editing the live policy does not touch the request's frozen rules.
      await prisma.approvalPolicy.update({ where: { id: policy.id }, data: { eligibleRoles: ["SENIOR_APPROVER"] } });
      expect(await joinRequest(socket, requestId)).toEqual({ ok: true });

      // Escalation (what checkEscalations does) moves to level 1: SENIOR_APPROVER only.
      await prisma.approvalRequest.update({ where: { id: requestId }, data: { escalationLevel: 1, policyId: fallback.id } });
      const after = await joinRequest(socket, requestId);
      expect(after.ok).toBe(false);
    } finally {
      socket.disconnect();
    }
  });

  it("TEST 16: the requester can still join their own request even after the policy's eligibleRoles change", async () => {
    const policy = await prisma.approvalPolicy.create({
      data: {
        actionType: requesterSurvivesType,
        quorumType: "N_OF_M",
        minApprovals: 1,
        eligibleRoles: ["APPROVER"],
        escalationTimeoutSec: 300,
      },
    });
    const request = await createRequest(requesterUser.token, requesterSurvivesType, 16);

    await prisma.approvalPolicy.update({ where: { id: policy.id }, data: { eligibleRoles: ["SENIOR_APPROVER"] } });

    const socket = connectSocket(baseUrl, requesterUser.token);
    try {
      await waitForConnect(socket);
      // requesterUser's role (MEMBER) was never in eligibleRoles before or
      // after this change -- access here is entirely via isRequester, which
      // is independent of the policy.
      const result = await joinRequest(socket, request.approvalRequest.id);
      expect(result).toEqual({ ok: true });
    } finally {
      socket.disconnect();
    }
  });
});
