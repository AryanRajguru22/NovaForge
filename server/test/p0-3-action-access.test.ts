import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { randomUUID } from "node:crypto";
import {
  startTestServer,
  stopTestServer,
  apiRequest,
  createUserWithToken,
  addMockPasskey,
  castVote,
  cleanupUsers,
  cleanupPolicies,
  runSuffix,
} from "./testServer.js";
import { prisma } from "../src/lib/prisma.js";

// P0-3: GET /actions/:id previously returned any action -- payload, votes and
// signatures -- to any signed-in user.

describe("P0-3: action detail authorization (IDOR)", () => {
  const actionType = `test:p03-${runSuffix}`;
  const secretMarker = `classified-${randomUUID()}`;
  const emails = {
    owner: `p03-owner-${runSuffix}@example.com`,
    stranger: `p03-stranger-${runSuffix}@example.com`,
    approver: `p03-approver-${runSuffix}@example.com`,
    voter: `p03-voter-${runSuffix}@example.com`,
    admin: `p03-admin-${runSuffix}@example.com`,
    superAdmin: `p03-super-${runSuffix}@example.com`,
  };
  const users: Record<keyof typeof emails, { id: string; token: string }> = {} as never;
  let actionId: string;

  beforeAll(async () => {
    await startTestServer();
    const roles = { owner: "MEMBER", stranger: "MEMBER", approver: "APPROVER", voter: "APPROVER", admin: "ADMIN", superAdmin: "SUPER_ADMIN" } as const;
    for (const key of Object.keys(emails) as (keyof typeof emails)[]) {
      const { user, token } = await createUserWithToken({ email: emails[key], role: roles[key] });
      users[key] = { id: user.id, token };
    }
    await addMockPasskey(users.voter.id);
    await prisma.approvalPolicy.create({
      data: { actionType, quorumType: "N_OF_M", minApprovals: 2, eligibleRoles: ["APPROVER"], escalationTimeoutSec: 600 },
    });
    const created = await apiRequest("/actions", {
      method: "POST",
      token: users.owner.token,
      body: { type: actionType, payload: { note: secretMarker } },
    });
    expect(created.status).toBe(201);
    actionId = created.data.action.id;

    const vote = await castVote(created.data.approvalRequest.id, users.voter, "APPROVE");
    expect(vote.status).toBe(200);
  });

  afterAll(async () => {
    await prisma.approvalVote.deleteMany({ where: { request: { policy: { actionType } } } });
    await prisma.approvalRequest.deleteMany({ where: { policy: { actionType } } });
    await prisma.sensitiveAction.deleteMany({ where: { type: actionType } });
    await cleanupPolicies([actionType]);
    await cleanupUsers(Object.values(emails));
    await stopTestServer();
  });

  const getAction = (token: string, id = actionId) => apiRequest(`/actions/${id}`, { token });

  it("User A owns the action; unrelated User B is DENIED with a response indistinguishable from a missing id", async () => {
    const denied = await getAction(users.stranger.token);
    const missing = await getAction(users.stranger.token, randomUUID());
    expect(denied.status).toBe(404);
    expect(denied).toEqual(missing);

    const body = JSON.stringify(denied.data);
    expect(body).not.toContain(secretMarker);
    expect(body).not.toMatch(/signature|votes|payload|approvalRequest/i);
  });

  it("the owner (requester) is allowed", async () => {
    const res = await getAction(users.owner.token);
    expect(res.status).toBe(200);
    expect(res.data.action.payload.note).toBe(secretMarker);
  });

  it("an authorized approver (eligible role under the request's policy) is allowed", async () => {
    const res = await getAction(users.approver.token);
    expect(res.status).toBe(200);
    expect(res.data.approvalRequest.votes).toHaveLength(1);
  });

  it("a user who voted keeps access even after losing the eligible role", async () => {
    await prisma.user.update({ where: { id: users.voter.id }, data: { role: "MEMBER" } });
    const res = await getAction(users.voter.token);
    expect(res.status).toBe(200);
    expect(res.data.approvalRequest.votes[0].signedStatement).toBeTruthy();
    await prisma.user.update({ where: { id: users.voter.id }, data: { role: "APPROVER" } });
  });

  it("ADMIN (policy manager) without an eligible role is DENIED", async () => {
    const res = await getAction(users.admin.token);
    expect(res.status).toBe(404);
    expect(JSON.stringify(res.data)).not.toContain(secretMarker);
  });

  it("SUPER_ADMIN (audit authority) is allowed", async () => {
    const res = await getAction(users.superAdmin.token);
    expect(res.status).toBe(200);
  });

  it("losing eligibility revokes access immediately (authorization reads live roles, not token claims)", async () => {
    await prisma.user.update({ where: { id: users.approver.id }, data: { role: "MEMBER" } });
    expect((await getAction(users.approver.token)).status).toBe(404);
    await prisma.user.update({ where: { id: users.approver.id }, data: { role: "APPROVER" } });
    expect((await getAction(users.approver.token)).status).toBe(200);
  });

  it("unauthenticated requests are rejected", async () => {
    expect((await apiRequest(`/actions/${actionId}`)).status).toBe(401);
  });

  it("the action list only ever contains the caller's own actions", async () => {
    const res = await apiRequest("/actions", { token: users.stranger.token });
    expect(res.status).toBe(200);
    expect(JSON.stringify(res.data)).not.toContain(secretMarker);
  });
});
