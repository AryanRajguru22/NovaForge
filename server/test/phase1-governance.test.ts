import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import {
  startTestServer,
  stopTestServer,
  apiRequest,
  createUserWithToken,
  addMockPasskey,
  authenticatorFor,
  governanceProof,
  castVote,
  createApprovalRequestWithSnapshot,
  cleanupUsers,
  cleanupPolicies,
  runSuffix,
} from "./testServer.js";
import { prisma } from "../src/lib/prisma.js";
import { checkEscalations } from "../src/lib/escalation.js";
import { computeSubjectDigest } from "../src/lib/approvalSignature.js";
import { MAX_ESCALATIONS } from "../src/lib/policySnapshot.js";

// Phase 1: governance integrity. Real Postgres, real software authenticator;
// nothing here bypasses authentication, signature verification or database
// constraints (the only trigger bypass is the same `session_replication_role`
// technique the audit suite uses to plant legacy data the application can no
// longer produce).

type Actor = { id: string; token: string };

const tag = `p1-${runSuffix}`;
const email = (name: string) => `${tag}-${name}@example.com`;
const typeName = (name: string) => `test:${tag}-${name}`;

describe("Phase 1: governance integrity", () => {
  const names = ["admin1", "admin2", "superA", "superB", "requester", "senior", "lowtrust", "noUV", "member", "ap1", "ap2", "ap3", "ap4", "ap5", "ap6", "ap7", "ap8", "ap9"];
  const emails = names.map(email);
  const actors: Record<string, Actor> = {};
  const createdTypes: string[] = [];
  const policyIds: string[] = [];

  /** Creates a policy directly (no revision => no separation-of-duties history). */
  async function directPolicy(name: string, data: Partial<{ quorumType: "N_OF_M" | "ROLE_BASED" | "WEIGHTED"; minApprovals: number; eligibleRoles: any[]; fallbackPolicyId: string | null; escalationTimeoutSec: number }> = {}) {
    const actionType = typeName(name);
    createdTypes.push(actionType);
    const policy = await prisma.approvalPolicy.create({
      data: { actionType, quorumType: "N_OF_M", minApprovals: 1, eligibleRoles: ["APPROVER"], escalationTimeoutSec: 300, ...data },
    });
    policyIds.push(policy.id);
    return policy;
  }

  /** Creates a policy through the API (revision + step-up), as an admin would. */
  async function apiPolicy(actor: Actor, name: string, body: Record<string, unknown>) {
    const actionType = typeName(name);
    createdTypes.push(actionType);
    const res = await apiRequest("/policies", {
      method: "POST",
      token: actor.token,
      body: { actionType, quorumType: "N_OF_M", minApprovals: 1, eligibleRoles: ["APPROVER"], ...body, response: await governanceProof(actor, "policy") },
    });
    if (res.status === 201) policyIds.push(res.data.id);
    return res;
  }

  async function putPolicy(actor: Actor, id: string, body: Record<string, unknown>) {
    return apiRequest(`/policies/${id}`, { method: "PUT", token: actor.token, body: { ...body, response: await governanceProof(actor, "policy") } });
  }

  async function createAction(actionType: string, amount = 1) {
    const res = await apiRequest("/actions", { method: "POST", token: actors.requester.token, body: { type: actionType, payload: { amount } } });
    expect(res.status).toBe(201);
    return { actionId: res.data.action.id as string, requestId: res.data.approvalRequest.id as string };
  }

  /** Polls until `check` holds (the background escalation timer may be mid-pass when checkEscalations() is called). */
  async function until(check: () => Promise<boolean>, what: string, timeoutMs = 10_000) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      await checkEscalations();
      if (await check()) return;
      if (Date.now() > deadline) throw new Error(`timed out waiting for: ${what}`);
      await new Promise((r) => setTimeout(r, 50));
    }
  }

  const levelsOf = (requestId: string) => prisma.approvalRequestPolicyLevel.findMany({ where: { requestId }, orderBy: { level: "asc" } });
  const auditCount = (where: Record<string, unknown>) => prisma.auditLog.count({ where });

  beforeAll(async () => {
    await startTestServer();
    await cleanupUsers(emails);
    const roles: Record<string, "ADMIN" | "SUPER_ADMIN" | "MEMBER" | "SENIOR_APPROVER" | "APPROVER"> = {
      admin1: "ADMIN", admin2: "ADMIN", superA: "SUPER_ADMIN", superB: "SUPER_ADMIN", requester: "MEMBER", senior: "SENIOR_APPROVER",
      lowtrust: "ADMIN", noUV: "ADMIN", member: "MEMBER",
    };
    for (const n of names) {
      const created = await createUserWithToken({ email: email(n), role: roles[n] ?? "APPROVER" });
      actors[n] = { id: created.user.id, token: created.token };
      if (n === "noUV") await addMockPasskey(created.user.id, { userVerified: false });
      else if (n !== "requester" && n !== "member") await addMockPasskey(created.user.id);
    }
  });

  afterAll(async () => {
    vi.useRealTimers();
    await prisma.approvalVote.deleteMany({ where: { request: { action: { type: { in: createdTypes } } } } });
    await prisma.approvalRequest.deleteMany({ where: { action: { type: { in: createdTypes } } } });
    await prisma.sensitiveAction.deleteMany({ where: { type: { in: createdTypes } } });
    await cleanupPolicies(createdTypes);
    await cleanupUsers(emails);
    await stopTestServer();
  });

  // ---------------------------------------------------------------------------
  describe("Task 1: immutable policy snapshots", () => {
    it("editing a policy does not alter an already-created request's effective rules", async () => {
      const policy = await directPolicy("edit-inflight", { minApprovals: 2, eligibleRoles: ["APPROVER"] });
      const { requestId } = await createAction(typeName("edit-inflight"));

      // An admin rewrites the live policy to something much weaker.
      const edit = await putPolicy(actors.admin1, policy.id, { minApprovals: 1, eligibleRoles: ["ADMIN"], escalationTimeoutSec: 5 });
      expect(edit.status).toBe(200);

      const [level] = await levelsOf(requestId);
      expect(level).toMatchObject({ level: 0, policyId: policy.id, quorumType: "N_OF_M", minApprovals: 2, eligibleRoles: ["APPROVER"], escalationTimeoutSec: 300, source: "CAPTURED" });

      // Still decided under the ORIGINAL rules: an APPROVER may vote, one vote is not enough, two are.
      const first = await castVote(requestId, actors.ap1, "APPROVE");
      expect(first.status).toBe(200);
      expect(first.data.requestStatus).toBe("PENDING");
      const second = await castVote(requestId, actors.ap2, "APPROVE");
      expect(second.status).toBe(200);
      expect(second.data.requestStatus).toBe("APPROVED");

      // The API presents the frozen rules, not the live ones.
      const view = await apiRequest(`/actions/${(await prisma.approvalRequest.findUniqueOrThrow({ where: { id: requestId } })).actionId}`, { token: actors.requester.token });
      expect(view.data.approvalRequest.policy).toMatchObject({ minApprovals: 2, eligibleRoles: ["APPROVER"], escalationTimeoutSec: 300 });

      // A request created AFTER the edit picks up the new rules.
      const { requestId: later } = await createAction(typeName("edit-inflight"), 2);
      expect((await levelsOf(later))[0]).toMatchObject({ minApprovals: 1, eligibleRoles: ["ADMIN"], escalationTimeoutSec: 5 });
    });

    it("captures the whole fallback chain at creation, immune to later edits of any policy in it", async () => {
      const f2 = await directPolicy("chain-f2", { eligibleRoles: ["ADMIN"], minApprovals: 1, escalationTimeoutSec: 30 });
      const f1 = await directPolicy("chain-f1", { eligibleRoles: ["SENIOR_APPROVER"], minApprovals: 2, escalationTimeoutSec: 20, fallbackPolicyId: f2.id });
      const root = await directPolicy("chain-root", { eligibleRoles: ["APPROVER"], minApprovals: 3, escalationTimeoutSec: 10, fallbackPolicyId: f1.id });
      const { requestId } = await createAction(typeName("chain-root"));

      const levels = await levelsOf(requestId);
      expect(levels.map((l) => [l.level, l.policyId, l.minApprovals, l.escalationTimeoutSec])).toEqual([
        [0, root.id, 3, 10],
        [1, f1.id, 2, 20],
        [2, f2.id, 1, 30],
      ]);

      // Rewiring and weakening the live policies afterwards changes nothing for this request.
      await prisma.approvalPolicy.update({ where: { id: root.id }, data: { fallbackPolicyId: null } });
      await prisma.approvalPolicy.update({ where: { id: f1.id }, data: { minApprovals: 1, eligibleRoles: ["MEMBER"] } });

      // Escalation walks the frozen chain: level 1 with f1's ORIGINAL rules, then level 2, then expiry.
      const pastExpiry = () => prisma.approvalRequest.update({ where: { id: requestId }, data: { expiresAt: new Date(Date.now() - 1000) } });

      const levelIs = (n: number) => async () => (await prisma.approvalRequest.findUniqueOrThrow({ where: { id: requestId } })).escalationLevel === n;
      await pastExpiry();
      await until(levelIs(1), "level 1");
      let req = await prisma.approvalRequest.findUniqueOrThrow({ where: { id: requestId } });
      expect(req).toMatchObject({ status: "PENDING", escalationLevel: 1, policyId: f1.id });
      expect(req.expiresAt.getTime()).toBeGreaterThan(Date.now() + 15_000); // f1's own 20s timeout
      expect(req.expiresAt.getTime()).toBeLessThan(Date.now() + 25_000);

      await pastExpiry();
      await until(levelIs(2), "level 2");
      req = await prisma.approvalRequest.findUniqueOrThrow({ where: { id: requestId } });
      expect(req).toMatchObject({ status: "PENDING", escalationLevel: 2, policyId: f2.id });

      // Last level: fail closed.
      await pastExpiry();
      await until(async () => (await prisma.approvalRequest.findUniqueOrThrow({ where: { id: requestId } })).status === "EXPIRED", "expiry");
      req = await prisma.approvalRequest.findUniqueOrThrow({ where: { id: requestId } });
      expect(req.status).toBe("EXPIRED");
      expect(req.escalationLevel).toBe(2);
      expect((await prisma.sensitiveAction.findUniqueOrThrow({ where: { id: req.actionId } })).status).toBe("EXPIRED");

      // The escalation steps were audited with their levels.
      const escalations = await prisma.auditLog.findMany({ where: { entityId: requestId, event: "ESCALATION_TRIGGERED" }, orderBy: { seq: "asc" } });
      expect(escalations.map((e) => (e.metadata as any).toLevel)).toEqual([1, 2]);
    });

    it("snapshot levels are immutable in the database, and a request without a snapshot fails closed", async () => {
      const policy = await directPolicy("immutable", { minApprovals: 1 });
      const { requestId } = await createAction(typeName("immutable"));
      await expect(prisma.approvalRequestPolicyLevel.updateMany({ where: { requestId }, data: { minApprovals: 1000 } })).rejects.toThrow(/immutable/);
      await expect(prisma.$executeRaw`UPDATE "ApprovalRequestPolicyLevel" SET "eligibleRoles" = '{MEMBER}' WHERE "requestId" = ${requestId}`).rejects.toThrow(/immutable/);
      expect((await levelsOf(requestId))[0].minApprovals).toBe(1);

      // A request with no snapshot (nothing in the application creates one) is never decided
      // from the live policy: voting is refused outright.
      const action = await prisma.sensitiveAction.create({
        data: { type: typeName("immutable"), payload: { n: 1 }, payloadDigest: computeSubjectDigest(typeName("immutable"), { n: 1 }), requestedById: actors.requester.id },
      });
      const bare = await prisma.approvalRequest.create({ data: { actionId: action.id, policyId: policy.id, expiresAt: new Date(Date.now() + 60_000) } });
      const options = await apiRequest(`/approvals/${bare.id}/options`, { method: "POST", token: actors.ap1.token, body: { decision: "APPROVE" } });
      expect(options.status).toBe(409);
      expect(options.data.error).toMatch(/no governing policy snapshot/);
    });

    it("a policy named by a request snapshot cannot be deleted, and neither can one used as a fallback", async () => {
      const fallback = await directPolicy("del-fallback");
      const root = await directPolicy("del-root", { fallbackPolicyId: fallback.id });
      const viaFallback = await apiRequest(`/policies/${fallback.id}`, { method: "DELETE", token: actors.admin1.token, body: { response: await governanceProof(actors.admin1, "policy") } });
      expect(viaFallback.status).toBe(400);
      expect(viaFallback.data.error).toMatch(/fallback/);

      await createAction(typeName("del-root"));
      await prisma.approvalPolicy.update({ where: { id: root.id }, data: { fallbackPolicyId: null } });
      const viaSnapshot = await apiRequest(`/policies/${fallback.id}`, { method: "DELETE", token: actors.admin1.token, body: { response: await governanceProof(actors.admin1, "policy") } });
      expect(viaSnapshot.status).toBe(400);
      expect(viaSnapshot.data.error).toMatch(/still reference it/);
    });
  });

  // ---------------------------------------------------------------------------
  describe("Task 2: voter attributes are frozen at vote time", () => {
    it("a later weight reduction does not rewrite an earlier vote's contribution (WEIGHTED)", async () => {
      await prisma.user.update({ where: { id: actors.ap3.id }, data: { voteWeight: 3 } });
      await prisma.user.update({ where: { id: actors.ap4.id }, data: { voteWeight: 2 } });
      await directPolicy("weighted", { quorumType: "WEIGHTED", minApprovals: 5, eligibleRoles: ["APPROVER"] });
      const { requestId } = await createAction(typeName("weighted"));

      const first = await castVote(requestId, actors.ap3, "APPROVE");
      expect(first.data.requestStatus).toBe("PENDING"); // 3 < 5
      const recorded = await prisma.approvalVote.findFirstOrThrow({ where: { requestId, approverId: actors.ap3.id } });
      expect(recorded).toMatchObject({ roleAtVote: "APPROVER", weightAtVote: 3, attributesSource: "CAPTURED" });

      // A super admin (fresh passkey proof) cuts ap3's weight to 1.
      const cut = await apiRequest(`/users/${actors.ap3.id}/weight`, {
        method: "PATCH",
        token: actors.superA.token,
        body: { voteWeight: 1, response: await governanceProof(actors.superA, "user") },
      });
      expect(cut.status).toBe(200);

      // Under the old "current weight" tally this would be 1 + 2 = 3 < 5 and stay PENDING.
      // The frozen weight gives 3 + 2 = 5 and the quorum is reached.
      const second = await castVote(requestId, actors.ap4, "APPROVE");
      expect(second.data.requestStatus).toBe("APPROVED");

      // The recorded value never moved.
      expect((await prisma.approvalVote.findFirstOrThrow({ where: { requestId, approverId: actors.ap3.id } })).weightAtVote).toBe(3);
      await prisma.user.update({ where: { id: actors.ap3.id }, data: { voteWeight: 1 } });
      await prisma.user.update({ where: { id: actors.ap4.id }, data: { voteWeight: 1 } });
    });

    it("a later demotion does not rewrite an earlier vote's role (ROLE_BASED)", async () => {
      await directPolicy("rolebased", { quorumType: "ROLE_BASED", minApprovals: 2, eligibleRoles: ["APPROVER", "SENIOR_APPROVER"] });
      const { requestId } = await createAction(typeName("rolebased"));

      const first = await castVote(requestId, actors.ap5, "APPROVE");
      expect(first.data.requestStatus).toBe("PENDING"); // SENIOR_APPROVER still missing

      const demote = await apiRequest(`/users/${actors.ap5.id}/role`, {
        method: "PATCH",
        token: actors.superA.token,
        body: { role: "MEMBER", response: await governanceProof(actors.superA, "user") },
      });
      expect(demote.status).toBe(200);

      // Old tally: roles {MEMBER, SENIOR_APPROVER} -> APPROVER missing -> stays PENDING.
      const second = await castVote(requestId, actors.senior, "APPROVE");
      expect(second.data.requestStatus).toBe("APPROVED");
      expect((await prisma.approvalVote.findFirstOrThrow({ where: { requestId, approverId: actors.ap5.id } })).roleAtVote).toBe("APPROVER");

      // And the demoted user can no longer vote on anything new (eligibility is checked against the live role).
      await directPolicy("rolebased-2");
      const { requestId: other } = await createAction(typeName("rolebased-2"));
      expect((await castVote(other, actors.ap5, "APPROVE")).status).toBe(403);
      await prisma.user.update({ where: { id: actors.ap5.id }, data: { role: "APPROVER" } });
    });

    it("recorded vote attributes are immutable in the database", async () => {
      const vote = await prisma.approvalVote.findFirstOrThrow({ where: { approverId: actors.ap3.id, request: { action: { type: typeName("weighted") } } } });
      await expect(prisma.approvalVote.update({ where: { id: vote.id }, data: { weightAtVote: 10 } })).rejects.toThrow();
      await expect(prisma.$executeRaw`UPDATE "ApprovalVote" SET "roleAtVote" = 'ADMIN' WHERE "id" = ${vote.id}`).rejects.toThrow();
    });
  });

  // ---------------------------------------------------------------------------
  describe("Task 3: governance mutations require fresh step-up and trust", () => {
    // Each case: how to call the mutation (given a body that may carry `response`) and how to see it did nothing.
    let policyId: string;
    let victim: Actor;

    const mutations = () => [
      { name: "policy create", actor: actors.admin1, kind: "policy" as const, call: (response?: unknown) => apiRequest("/policies", { method: "POST", token: actors.admin1.token, body: { actionType: typeName("su-created"), quorumType: "N_OF_M", minApprovals: 1, eligibleRoles: ["APPROVER"], response } }) },
      { name: "policy update", actor: actors.admin1, kind: "policy" as const, call: (response?: unknown) => apiRequest(`/policies/${policyId}`, { method: "PUT", token: actors.admin1.token, body: { minApprovals: 9, response } }) },
      { name: "policy delete", actor: actors.admin1, kind: "policy" as const, call: (response?: unknown) => apiRequest(`/policies/${policyId}`, { method: "DELETE", token: actors.admin1.token, body: { response } }) },
      { name: "user role", actor: actors.superA, kind: "user" as const, call: (response?: unknown) => apiRequest(`/users/${victim.id}/role`, { method: "PATCH", token: actors.superA.token, body: { role: "ADMIN", response } }) },
      { name: "user weight", actor: actors.superA, kind: "user" as const, call: (response?: unknown) => apiRequest(`/users/${victim.id}/weight`, { method: "PATCH", token: actors.superA.token, body: { voteWeight: 9, response } }) },
      { name: "user status", actor: actors.superA, kind: "user" as const, call: (response?: unknown) => apiRequest(`/users/${victim.id}/status`, { method: "PATCH", token: actors.superA.token, body: { status: "DISABLED", response } }) },
      { name: "user invitation", actor: actors.superA, kind: "enrollment" as const, call: (response?: unknown) => apiRequest("/users/invitations", { method: "POST", token: actors.superA.token, body: { email: email("invitee"), name: "Invitee", role: "SUPER_ADMIN", response } }) },
      { name: "enrollment token", actor: actors.superA, kind: "enrollment" as const, call: (response?: unknown) => apiRequest(`/users/${victim.id}/enrollment-token`, { method: "POST", token: actors.superA.token, body: { response } }) },
      { name: "user delete", actor: actors.superA, kind: "user" as const, call: (response?: unknown) => apiRequest(`/users/${victim.id}`, { method: "DELETE", token: actors.superA.token, body: { response } }) },
    ];

    async function assertUntouched() {
      const policy = await prisma.approvalPolicy.findUniqueOrThrow({ where: { id: policyId } });
      expect(policy.minApprovals).toBe(1);
      expect(await prisma.approvalPolicy.count({ where: { actionType: typeName("su-created") } })).toBe(0);
      const user = await prisma.user.findUniqueOrThrow({ where: { id: victim.id } });
      expect(user).toMatchObject({ role: "APPROVER", voteWeight: 1, status: "ACTIVE" });
      expect(await prisma.user.count({ where: { email: email("invitee") } })).toBe(0);
      expect(await prisma.enrollmentToken.count({ where: { userId: victim.id } })).toBe(0);
    }

    beforeAll(async () => {
      policyId = (await directPolicy("su-target")).id;
      victim = actors.ap6;
    });

    it("every mutation is refused without a step-up proof (403 STEP_UP_REQUIRED) and the refusal is audited", async () => {
      for (const m of mutations()) {
        const before = await auditCount({ event: "GOVERNANCE_STEP_UP_FAILED", actorId: m.actor.id });
        const res = await m.call(undefined);
        expect(res.status, m.name).toBe(403);
        expect(res.data.code, m.name).toBe("STEP_UP_REQUIRED");
        expect(await auditCount({ event: "GOVERNANCE_STEP_UP_FAILED", actorId: m.actor.id }), m.name).toBe(before + 1);
      }
      await assertUntouched();
      const last = await prisma.auditLog.findFirstOrThrow({ where: { event: "GOVERNANCE_STEP_UP_FAILED", actorId: actors.superA.id }, orderBy: { seq: "desc" } });
      expect(last.metadata).toMatchObject({ operation: "user:delete", purpose: "user-governance", reason: "missing" });
    });

    it("an invalid proof is refused: garbage, a proof signed by someone else's key, a proof for the other purpose", async () => {
      const optionsPath = (kind: "policy" | "user" | "enrollment") =>
        kind === "policy" ? "/policies/step-up/options" : kind === "user" ? "/users/governance/step-up/options" : "/users/step-up/options";
      for (const m of mutations()) {
        // Garbage assertion object.
        const garbage = await m.call({ id: "x", rawId: "x", type: "public-key", response: {} });
        expect(garbage.status, `${m.name} garbage`).toBe(400);
        expect(garbage.data.code).toBe("STEP_UP_FAILED");

        // Valid challenge, but signed by a different user's authenticator.
        const options = await apiRequest(optionsPath(m.kind), { method: "POST", token: m.actor.token, body: {} });
        const foreign = authenticatorFor(actors.ap1.id).createAssertion(options.data.challenge);
        const res = await m.call(foreign);
        expect(res.status, `${m.name} foreign`).toBe(400);
        expect(res.data.code).toBe("STEP_UP_FAILED");
      }

      // Purpose binding: super admin A holds both privileges; a proof minted for one purpose is
      // worthless for the other (there is no outstanding challenge for it).
      const policyProof = await governanceProof(actors.superA, "policy");
      const onUser = await apiRequest(`/users/${victim.id}/weight`, { method: "PATCH", token: actors.superA.token, body: { voteWeight: 9, response: policyProof } });
      expect(onUser.status).toBe(400);
      const userProof = await governanceProof(actors.superA, "user");
      const onPolicy = await apiRequest(`/policies/${policyId}`, { method: "PUT", token: actors.superA.token, body: { minApprovals: 9, response: userProof } });
      expect(onPolicy.status).toBe(400);
      await assertUntouched();
    });

    it("a proof is single-use: replaying a valid assertion is refused", async () => {
      const response = await governanceProof(actors.admin1, "policy");
      const first = await apiRequest(`/policies/${policyId}`, { method: "PUT", token: actors.admin1.token, body: { escalationTimeoutSec: 301, response } });
      expect(first.status).toBe(200);
      const replay = await apiRequest(`/policies/${policyId}`, { method: "PUT", token: actors.admin1.token, body: { escalationTimeoutSec: 777, response } });
      expect(replay.status).toBe(400);
      expect(replay.data.code).toBe("STEP_UP_FAILED");
      expect((await prisma.approvalPolicy.findUniqueOrThrow({ where: { id: policyId } })).escalationTimeoutSec).toBe(301);
    });

    it("a proof expires: a challenge older than its lifetime is refused", async () => {
      // Issue the challenge "6 minutes ago" (past the 5 minute challenge TTL), then submit it now. The
      // clock is only moved while the challenge is issued -- an options request writes no audit row --
      // because the audit chain clamps timestamps to be non-decreasing, so no audit event may ever be
      // written under a future clock.
      let response;
      vi.useFakeTimers({ toFake: ["Date"], now: Date.now() - 6 * 60 * 1000 });
      try {
        response = await governanceProof(actors.superA, "user");
      } finally {
        vi.useRealTimers();
      }
      const res = await apiRequest(`/users/${victim.id}/weight`, { method: "PATCH", token: actors.superA.token, body: { voteWeight: 7, response } });
      expect(res.status).toBe(400);
      expect(res.data.error).toMatch(/expired/i);
      expect((await prisma.user.findUniqueOrThrow({ where: { id: victim.id } })).voteWeight).toBe(1);
    });

    it("a passkey assertion without user verification is refused", async () => {
      const res = await apiRequest(`/policies/${policyId}`, { method: "PUT", token: actors.noUV.token, body: { minApprovals: 9, response: await governanceProof(actors.noUV, "policy") } });
      expect(res.status).toBe(400);
      expect(res.data.code).toBe("STEP_UP_FAILED");
      expect((await prisma.approvalPolicy.findUniqueOrThrow({ where: { id: policyId } })).minApprovals).toBe(1);
    });

    it("a session whose effective trust has decayed is refused, and the refusal is audited", async () => {
      await prisma.session.updateMany({ where: { userId: actors.lowtrust.id }, data: { lastVerifiedAt: new Date(Date.now() - 30 * 3_600_000) } });
      const before = await auditCount({ event: "GOVERNANCE_TRUST_DENIED", actorId: actors.lowtrust.id });
      const options = await apiRequest("/policies/step-up/options", { method: "POST", token: actors.lowtrust.token, body: {} });
      expect(options.status).toBe(403);
      const put = await apiRequest(`/policies/${policyId}`, { method: "PUT", token: actors.lowtrust.token, body: { minApprovals: 9, response: {} } });
      expect(put.status).toBe(403);
      expect(put.data.required).toBe(50);
      expect(await auditCount({ event: "GOVERNANCE_TRUST_DENIED", actorId: actors.lowtrust.id })).toBe(before + 2);
      // Role-granting invitations are gated by the same trust check (superA's own session is healthy, so
      // decay a dedicated super admin's session instead).
      await prisma.session.updateMany({ where: { userId: actors.superB.id }, data: { lastVerifiedAt: new Date(Date.now() - 30 * 3_600_000) } });
      const invite = await apiRequest("/users/invitations", { method: "POST", token: actors.superB.token, body: { email: email("invitee"), name: "Invitee", role: "SUPER_ADMIN", response: {} } });
      expect(invite.status).toBe(403);
      expect(invite.data.required).toBe(50);
      await prisma.session.updateMany({ where: { userId: actors.superB.id }, data: { lastVerifiedAt: new Date() } });
      expect(await prisma.user.count({ where: { email: email("invitee") } })).toBe(0);
      expect((await prisma.approvalPolicy.findUniqueOrThrow({ where: { id: policyId } })).minApprovals).toBe(1);
    });

    it("role-based access is unchanged: non-admins cannot touch policies, admins cannot touch users", async () => {
      expect((await apiRequest("/policies/step-up/options", { method: "POST", token: actors.member.token, body: {} })).status).toBe(403);
      expect((await apiRequest("/users/governance/step-up/options", { method: "POST", token: actors.admin1.token, body: {} })).status).toBe(403);
      const asAdmin = await apiRequest(`/users/${victim.id}/role`, { method: "PATCH", token: actors.admin1.token, body: { role: "ADMIN", response: {} } });
      expect(asAdmin.status).toBe(403);
      await assertUntouched();
    });

    it("with a valid proof the mutation succeeds, is audited with the proving credential, and policy edits leave a revision", async () => {
      const edit = await putPolicy(actors.admin1, policyId, { minApprovals: 1, escalationTimeoutSec: 300 });
      expect(edit.status).toBe(200);
      const audit = await prisma.auditLog.findFirstOrThrow({ where: { entityId: policyId, event: "POLICY_UPDATED" }, orderBy: { seq: "desc" } });
      const credential = await prisma.credential.findFirstOrThrow({ where: { userId: actors.admin1.id, type: "PASSKEY" } });
      expect(audit.actorId).toBe(actors.admin1.id);
      expect(audit.metadata).toMatchObject({ stepUpCredentialId: credential.id });
      const revisions = await prisma.approvalPolicyRevision.findMany({ where: { policyId }, orderBy: { version: "asc" } });
      expect(revisions.length).toBeGreaterThanOrEqual(2);
      expect(revisions.map((r) => r.version)).toEqual(revisions.map((_, i) => i + 1));
      expect(revisions.at(-1)).toMatchObject({ changeType: "UPDATED", changedById: actors.admin1.id });
      await expect(prisma.approvalPolicyRevision.update({ where: { id: revisions[0].id }, data: { changeType: "X" } })).rejects.toThrow();
      await expect(prisma.approvalPolicyRevision.delete({ where: { id: revisions[0].id } })).rejects.toThrow();
    });

    it("the last active super admin cannot be removed, even by two super admins demoting each other at once", async () => {
      // Make exactly superA and superB the only active super admins (restored afterwards).
      const others = await prisma.user.findMany({ where: { role: "SUPER_ADMIN", status: "ACTIVE", id: { notIn: [actors.superA.id, actors.superB.id] } }, select: { id: true } });
      await prisma.user.updateMany({ where: { id: { in: others.map((o) => o.id) } }, data: { status: "DISABLED" } });
      try {
        const demote = async (actor: Actor, target: Actor) =>
          apiRequest(`/users/${target.id}/role`, {
            method: "PATCH",
            token: actor.token,
            body: { role: "ADMIN", response: await governanceProof(actor, "user") },
          });

        // Deterministic interleaving: hold the super-admin-set lock so BOTH requests pass authorisation
        // and step-up before either can commit, then release. Without the lock + in-transaction recount,
        // each would see the other still active and both would succeed, leaving no super admin.
        let pending!: Promise<Awaited<ReturnType<typeof demote>>[]>;
        await prisma.$transaction(async (tx) => {
          await tx.$executeRaw`SELECT pg_advisory_xact_lock(727002::bigint)`;
          pending = Promise.all([demote(actors.superA, actors.superB), demote(actors.superB, actors.superA)]);
          const deadline = Date.now() + 10_000;
          for (;;) {
            const [{ count }] = await tx.$queryRaw<{ count: bigint }[]>`SELECT COUNT(*)::bigint AS count FROM pg_locks WHERE locktype = 'advisory' AND NOT granted`;
            if (count >= 2n) break;
            if (Date.now() > deadline) throw new Error("both demotions never reached the lock");
            await new Promise((r) => setTimeout(r, 25));
          }
        }, { timeout: 30_000, maxWait: 5_000 });
        // (the transaction has committed and released the lock)
        const settled = await pending;
        expect(settled.map((r) => r.status).sort()).toEqual([200, 400]);
        expect(await prisma.user.count({ where: { role: "SUPER_ADMIN", status: "ACTIVE" } })).toBe(1);
      } finally {
        await prisma.user.updateMany({ where: { id: { in: [actors.superA.id, actors.superB.id] } }, data: { role: "SUPER_ADMIN" } });
        await prisma.user.updateMany({ where: { id: { in: others.map((o) => o.id) } }, data: { status: "ACTIVE" } });
      }
    });
  });

  // ---------------------------------------------------------------------------
  describe("Task 3b: a policy editor cannot approve requests governed by their change", () => {
    it("blocks the author of the captured revision on options, vote and the pending list, but not other admins", async () => {
      // admin1 authors the policy through the API; admin1 and admin2 are both eligible approver roles.
      const created = await apiPolicy(actors.admin1, "sod", { eligibleRoles: ["ADMIN", "APPROVER"], minApprovals: 2 });
      expect(created.status).toBe(201);
      const { requestId } = await createAction(typeName("sod"));
      expect((await levelsOf(requestId))[0].conflictedUserIds).toEqual([actors.admin1.id]);

      const options = await apiRequest(`/approvals/${requestId}/options`, { method: "POST", token: actors.admin1.token, body: { decision: "APPROVE" } });
      expect(options.status).toBe(403);
      expect(options.data.error).toMatch(/changed a policy/);
      const vote = await castVote(requestId, actors.admin1, "APPROVE");
      expect(vote.status).toBe(403);
      expect(await prisma.approvalVote.count({ where: { requestId } })).toBe(0);

      const pendingFor = async (a: Actor) => (await apiRequest("/approvals/pending", { token: a.token })).data.map((r: any) => r.id);
      expect(await pendingFor(actors.admin1)).not.toContain(requestId);
      expect(await pendingFor(actors.admin2)).toContain(requestId);

      // A second admin who did not touch the policy may vote.
      expect((await castVote(requestId, actors.admin2, "APPROVE")).status).toBe(200);
    });

    it("the restriction is fixed when the request is created: a later edit never disqualifies retroactively, an earlier one always does", async () => {
      // Direct-created policy (no revisions); request created; admin2 edits afterwards -> request is NOT conflicted.
      const policy = await directPolicy("sod-after", { eligibleRoles: ["ADMIN"], minApprovals: 1 });
      const { requestId: before } = await createAction(typeName("sod-after"));
      expect((await putPolicy(actors.admin2, policy.id, { escalationTimeoutSec: 400 })).status).toBe(200);
      const { requestId: after } = await createAction(typeName("sod-after"), 2);

      expect((await levelsOf(before))[0].conflictedUserIds).toEqual([]);
      expect((await levelsOf(after))[0].conflictedUserIds).toEqual([actors.admin2.id]);

      // The edit cannot retroactively disqualify admin2 from the older request...
      expect((await apiRequest(`/approvals/${before}/options`, { method: "POST", token: actors.admin2.token, body: { decision: "APPROVE" } })).status).toBe(200);
      // ...but they are disqualified from the newer one, which was created under their revision.
      expect((await castVote(after, actors.admin2, "APPROVE")).status).toBe(403);
    });

    it("is race-free: a vote racing the edit is judged under one coherent snapshot", async () => {
      // Policy created directly; request created; then admin2 edits WHILE admin2 votes on that older request.
      const policy = await directPolicy("sod-race", { eligibleRoles: ["ADMIN"], minApprovals: 1 });
      const { requestId } = await createAction(typeName("sod-race"));
      const [edit, vote] = await Promise.all([putPolicy(actors.admin2, policy.id, { escalationTimeoutSec: 450 }), castVote(requestId, actors.admin2, "APPROVE")]);
      expect(edit.status).toBe(200);
      // The request predates the edit, so its snapshot has no conflict: the vote is judged only under that snapshot.
      expect(vote.status).toBe(200);
      expect((await levelsOf(requestId))[0].conflictedUserIds).toEqual([]);
    });
  });

  // ---------------------------------------------------------------------------
  describe("Task 6.2: concurrent policy modification cannot bypass the governing policy", () => {
    it("a vote racing a weakening edit is decided under the original rules every time", async () => {
      for (let i = 0; i < 4; i++) {
        const policy = await directPolicy(`race-vote-${i}`, { minApprovals: 2, eligibleRoles: ["APPROVER"] });
        const { requestId } = await createAction(typeName(`race-vote-${i}`), i);
        const [vote, edit] = await Promise.all([
          castVote(requestId, actors.ap7, "APPROVE"),
          putPolicy(actors.admin1, policy.id, { minApprovals: 1, eligibleRoles: ["ADMIN"] }),
        ]);
        expect(edit.status).toBe(200);
        expect(vote.status).toBe(200); // still an eligible approver under the frozen rules
        const request = await prisma.approvalRequest.findUniqueOrThrow({ where: { id: requestId } });
        expect(request.status, `iteration ${i}`).toBe("PENDING"); // one vote can never satisfy the original 2
        expect((await levelsOf(requestId))[0]).toMatchObject({ minApprovals: 2, eligibleRoles: ["APPROVER"] });
      }
    });

    it("a request created while the policy is being edited captures one coherent revision", async () => {
      const policy = await directPolicy("race-create", { minApprovals: 2 });
      let previous = 2;
      for (let i = 0; i < 6; i++) {
        const next = 3 + i;
        const [created, edit] = await Promise.all([
          apiRequest("/actions", { method: "POST", token: actors.requester.token, body: { type: typeName("race-create"), payload: { i } } }),
          putPolicy(actors.admin1, policy.id, { minApprovals: next }),
        ]);
        expect(created.status).toBe(201);
        expect(edit.status).toBe(200);
        const [level] = await levelsOf(created.data.approvalRequest.id);
        if (level.policyRevisionId === null) {
          // Captured before any revision existed => entirely before this edit.
          expect(level.minApprovals).toBe(previous);
          expect(level.conflictedUserIds).toEqual([]);
        } else {
          const revision = await prisma.approvalPolicyRevision.findUniqueOrThrow({ where: { id: level.policyRevisionId } });
          // The captured values are exactly those of the captured revision (never a mix),
          // and its author is recorded as conflicted.
          expect((revision.snapshot as any).minApprovals).toBe(level.minApprovals);
          expect(level.conflictedUserIds).toContain(actors.admin1.id);
          expect([previous, next]).toContain(level.minApprovals);
        }
        previous = next;
      }
    });
  });

  // ---------------------------------------------------------------------------
  describe("Task 4: fallback policy cycles", () => {
    it("rejects A -> B -> A, longer cycles, and over-long chains, with a clear error", async () => {
      const a = await directPolicy("cyc-a");
      const b = await directPolicy("cyc-b", { fallbackPolicyId: a.id }); // b -> a
      const c = await directPolicy("cyc-c", { fallbackPolicyId: b.id }); // c -> b -> a

      const twoCycle = await putPolicy(actors.admin1, a.id, { fallbackPolicyId: b.id }); // a -> b -> a
      expect(twoCycle.status).toBe(400);
      expect(twoCycle.data.error).toMatch(/cycle/i);

      const threeCycle = await putPolicy(actors.admin1, a.id, { fallbackPolicyId: c.id }); // a -> c -> b -> a
      expect(threeCycle.status).toBe(400);
      expect(threeCycle.data.error).toMatch(/cycle/i);

      expect((await prisma.approvalPolicy.findUniqueOrThrow({ where: { id: a.id } })).fallbackPolicyId).toBeNull();

      // A legitimate extension of the chain is fine.
      expect((await putPolicy(actors.admin1, c.id, { escalationTimeoutSec: 99 })).status).toBe(200);

      // Chain length: MAX_ESCALATIONS fallbacks are allowed, one more is not.
      let previous = a.id;
      for (let i = 0; i < MAX_ESCALATIONS; i++) {
        // a has no fallback; build x_i -> x_(i-1) -> ... -> a, up to MAX_ESCALATIONS policies in the chain
        const created = await apiPolicy(actors.admin2, `cyc-chain-${i}`, { fallbackPolicyId: previous });
        expect(created.status, `link ${i}`).toBe(201);
        previous = created.data.id;
      }
      const tooLong = await apiPolicy(actors.admin2, "cyc-chain-over", { fallbackPolicyId: previous });
      expect(tooLong.status).toBe(400);
      expect(tooLong.data.error).toMatch(/at most/);
    });

    it("two concurrent updates that would jointly form a cycle: exactly one wins", async () => {
      for (let trial = 0; trial < 4; trial++) {
        const a = await directPolicy(`cyc-race-a-${trial}`);
        const b = await directPolicy(`cyc-race-b-${trial}`);
        // Different admins: a step-up challenge is per user, so two in-flight proofs need two users.
        const results = await Promise.all([
          putPolicy(actors.admin1, a.id, { fallbackPolicyId: b.id }),
          putPolicy(actors.admin2, b.id, { fallbackPolicyId: a.id }),
        ]);
        expect(results.map((r) => r.status).sort(), `trial ${trial}`).toEqual([200, 400]);
        const [pa, pb] = await Promise.all([a, b].map((p) => prisma.approvalPolicy.findUniqueOrThrow({ where: { id: p.id } })));
        expect(Number(pa.fallbackPolicyId === b.id) + Number(pb.fallbackPolicyId === a.id)).toBe(1);
      }
    });

    it("the database itself rejects a cycle from any writer, including concurrent raw updates", async () => {
      const a = await directPolicy("cyc-db-a");
      const b = await directPolicy("cyc-db-b");
      await expect(prisma.approvalPolicy.update({ where: { id: a.id }, data: { fallbackPolicyId: a.id } })).rejects.toThrow(/cycle/);

      const settled = await Promise.allSettled([
        prisma.$executeRaw`UPDATE "ApprovalPolicy" SET "fallbackPolicyId" = ${b.id} WHERE "id" = ${a.id}`,
        prisma.$executeRaw`UPDATE "ApprovalPolicy" SET "fallbackPolicyId" = ${a.id} WHERE "id" = ${b.id}`,
      ]);
      expect(settled.filter((s) => s.status === "fulfilled")).toHaveLength(1);
      expect(settled.filter((s) => s.status === "rejected")).toHaveLength(1);
    });

    it("escalation terminates and fails closed even when legacy data already contains a cycle", async () => {
      const a = await directPolicy("cyc-legacy-a", { escalationTimeoutSec: 30 });
      const b = await directPolicy("cyc-legacy-b", { escalationTimeoutSec: 30 });
      // Plant A -> B -> A the way pre-Phase-1 data could contain it (triggers off for this transaction only).
      await prisma.$transaction(async (tx) => {
        await tx.$executeRawUnsafe("SET LOCAL session_replication_role = replica");
        await tx.$executeRaw`UPDATE "ApprovalPolicy" SET "fallbackPolicyId" = ${b.id} WHERE "id" = ${a.id}`;
        await tx.$executeRaw`UPDATE "ApprovalPolicy" SET "fallbackPolicyId" = ${a.id} WHERE "id" = ${b.id}`;
      });
      try {
        const { requestId } = await createAction(typeName("cyc-legacy-a"));
        const levels = await levelsOf(requestId);
        expect(levels.map((l) => l.policyId)).toEqual([a.id, b.id]); // chain cut where it would revisit

        const expire = () => prisma.approvalRequest.update({ where: { id: requestId }, data: { expiresAt: new Date(Date.now() - 1000) } });
        await expire();
        await until(async () => (await prisma.approvalRequest.findUniqueOrThrow({ where: { id: requestId } })).escalationLevel === 1, "level 1");
        await expire();
        await until(async () => (await prisma.approvalRequest.findUniqueOrThrow({ where: { id: requestId } })).status === "EXPIRED", "expiry"); // no level 2: EXPIRED, not A again
        const final = await prisma.approvalRequest.findUniqueOrThrow({ where: { id: requestId } });
        expect(final.status).toBe("EXPIRED");
        expect(final.escalationLevel).toBe(1);
        await checkEscalations(); // nothing left to do
        expect((await prisma.approvalRequest.findUniqueOrThrow({ where: { id: requestId } })).status).toBe("EXPIRED");
      } finally {
        await prisma.approvalPolicy.update({ where: { id: a.id }, data: { fallbackPolicyId: null } });
        await prisma.approvalPolicy.update({ where: { id: b.id }, data: { fallbackPolicyId: null } });
      }
    });

    it("a request with no fallback expires after its timeout (fail closed)", async () => {
      await directPolicy("no-fallback");
      const { requestId } = await createAction(typeName("no-fallback"));
      await prisma.approvalRequest.update({ where: { id: requestId }, data: { expiresAt: new Date(Date.now() - 1000) } });
      await until(async () => (await prisma.approvalRequest.findUniqueOrThrow({ where: { id: requestId } })).status === "EXPIRED", "expiry");
      const request = await prisma.approvalRequest.findUniqueOrThrow({ where: { id: requestId } });
      expect(request).toMatchObject({ status: "EXPIRED", escalationLevel: 0 });
    });
  });

  // ---------------------------------------------------------------------------
  describe("snapshot capture for requests built outside the API", () => {
    it("createApprovalRequestWithSnapshot uses the production capture", async () => {
      const policy = await directPolicy("helper", { minApprovals: 4 });
      const action = await prisma.sensitiveAction.create({
        data: { type: typeName("helper"), payload: { n: 1 }, payloadDigest: computeSubjectDigest(typeName("helper"), { n: 1 }), requestedById: actors.requester.id },
      });
      const request = await createApprovalRequestWithSnapshot({ actionId: action.id, policyId: policy.id, expiresAt: new Date(Date.now() + 60_000) });
      expect((await levelsOf(request.id))[0]).toMatchObject({ minApprovals: 4, source: "CAPTURED" });
    });
  });
});
