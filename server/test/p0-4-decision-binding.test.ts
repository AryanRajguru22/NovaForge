import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createHash } from "node:crypto";
import { isoBase64URL } from "@simplewebauthn/server/helpers";
import {
  startTestServer,
  stopTestServer,
  apiRequest,
  createUserWithToken,
  addMockPasskey,
  authenticatorFor,
  castVote,
  createApprovalRequestWithSnapshot,
  cleanupUsers,
  cleanupPolicies,
  runSuffix,
} from "./testServer.js";
import { SoftAuthenticator } from "./softAuthenticator.js";
import { prisma } from "../src/lib/prisma.js";
import { env } from "../src/lib/env.js";
import { canonicalJson } from "../src/lib/canonicalJson.js";
import {
  computeSubjectDigest,
  parseStatement,
  statementChallenge,
  verifyStoredVoteEvidence,
  type StoredVoteEvidence,
} from "../src/lib/approvalSignature.js";

// P0-4: the WebAuthn signature must cover the decision and its exact context.
// Every assertion here is produced by a real software authenticator and
// checked by the real WebAuthn verifier.

describe("P0-4: approval decisions are cryptographically bound to the signature", () => {
  const actionType = `test:p04-${runSuffix}`;
  const emails = [
    `p04-requester-${runSuffix}@example.com`,
    `p04-approver-${runSuffix}@example.com`,
    `p04-approver2-${runSuffix}@example.com`,
    `p04-nouv-${runSuffix}@example.com`,
  ];
  let requester: { id: string; token: string };
  let approver: { id: string; token: string };
  let approver2: { id: string; token: string };
  let noUvApprover: { id: string; token: string };
  const expected = { rpId: env.rpId, origin: env.rpOrigin };

  async function createRequest(payload: object = { amount: Math.random() }) {
    const res = await apiRequest("/actions", { method: "POST", token: requester.token, body: { type: actionType, payload } });
    expect(res.status).toBe(201);
    return { actionId: res.data.action.id as string, requestId: res.data.approvalRequest.id as string };
  }

  async function options(requestId: string, voter: { token: string }, decision: string, reason?: string) {
    const res = await apiRequest(`/approvals/${requestId}/options`, { method: "POST", token: voter.token, body: { decision, reason } });
    expect(res.status).toBe(200);
    return res.data as { challenge: string; statement: string };
  }

  const submit = (requestId: string, voter: { token: string }, body: object) =>
    apiRequest(`/approvals/${requestId}/vote`, { method: "POST", token: voter.token, body });

  const voteCount = (requestId: string) => prisma.approvalVote.count({ where: { requestId } });

  beforeAll(async () => {
    await startTestServer();
    const r = await createUserWithToken({ email: emails[0], role: "MEMBER" });
    const a = await createUserWithToken({ email: emails[1], role: "APPROVER" });
    const a2 = await createUserWithToken({ email: emails[2], role: "APPROVER" });
    const nu = await createUserWithToken({ email: emails[3], role: "APPROVER" });
    requester = { id: r.user.id, token: r.token };
    approver = { id: a.user.id, token: a.token };
    approver2 = { id: a2.user.id, token: a2.token };
    noUvApprover = { id: nu.user.id, token: nu.token };
    await addMockPasskey(approver.id);
    await addMockPasskey(approver2.id);
    await addMockPasskey(noUvApprover.id, { userVerified: false });
    await prisma.approvalPolicy.create({
      data: { actionType, quorumType: "N_OF_M", minApprovals: 2, eligibleRoles: ["APPROVER"], escalationTimeoutSec: 600 },
    });
  });

  afterAll(async () => {
    await prisma.approvalVote.deleteMany({ where: { request: { policy: { actionType } } } });
    await prisma.approvalRequest.deleteMany({ where: { policy: { actionType } } });
    await prisma.sensitiveAction.deleteMany({ where: { type: actionType } });
    await cleanupPolicies([actionType]);
    await cleanupUsers(emails);
    await stopTestServer();
  });

  describe("the signing protocol", () => {
    it("the WebAuthn challenge is SHA-256 of a canonical statement naming request, action, subject digest, approver and decision", async () => {
      const { actionId, requestId } = await createRequest({ block: "B-1", window: "03:20-04:05" });
      const opts = await options(requestId, approver, "POSTPONE", "Operational requirement");
      const statement = parseStatement(opts.statement)!;
      expect(statement).not.toBeNull();
      expect(canonicalJson(statement)).toBe(opts.statement);
      expect(opts.challenge).toBe(statementChallenge(opts.statement));
      const action = await prisma.sensitiveAction.findUniqueOrThrow({ where: { id: actionId } });
      expect(statement).toMatchObject({
        requestId,
        actionId,
        actionType,
        approverId: approver.id,
        decision: "POSTPONE",
        reason: "Operational requirement",
        subjectDigest: action.payloadDigest,
        rpId: env.rpId,
      });
      expect(action.payloadDigest).toBe(computeSubjectDigest(actionType, { block: "B-1", window: "03:20-04:05" }));
    });

    it("a correctly signed vote is recorded with full evidence that independently re-verifies", async () => {
      const { actionId, requestId } = await createRequest();
      const res = await castVote(requestId, approver, "APPROVE");
      expect(res.status).toBe(200);
      const vote = await prisma.approvalVote.findFirstOrThrow({ where: { requestId } });
      const action = await prisma.sensitiveAction.findUniqueOrThrow({ where: { id: actionId } });
      expect(await verifyStoredVoteEvidence(vote, action, expected)).toEqual({ valid: true, errors: [] });

      const auditEvent = await prisma.auditLog.findFirstOrThrow({ where: { entityId: vote.id, event: "VOTE_CAST" } });
      expect((auditEvent.metadata as { statementHash: string }).statementHash).toBe(vote.statementHash);
    });

    it("stores the payload losslessly, so approvers sign exactly what was requested (17-significant-digit numbers included)", async () => {
      // Prisma 5's Json write path would store 0.38331432302637536 as
      // 0.3833143230263754; payloads are written with an exact ::jsonb cast.
      const payload = { risk: 0.38331432302637536, scores: [0.20213987566293812, 1e21, -0], label: "B87" };
      const created = await apiRequest("/actions", { method: "POST", token: requester.token, body: { type: actionType, payload } });
      expect(created.status).toBe(201);
      const stored = await prisma.sensitiveAction.findUniqueOrThrow({ where: { id: created.data.action.id } });
      expect(stored.payload).toEqual(JSON.parse(JSON.stringify(payload)));
      expect(stored.payloadDigest).toBe(computeSubjectDigest(actionType, JSON.parse(JSON.stringify(payload))));
      expect((await castVote(created.data.approvalRequest.id, approver, "APPROVE")).status).toBe(200);
    });

    it("POSTPONE is a first-class signed decision that ends the request", async () => {
      const { requestId } = await createRequest();
      const res = await castVote(requestId, approver, "POSTPONE", "Operational requirement");
      expect(res.status).toBe(200);
      expect(res.data.requestStatus).toBe("POSTPONED");
      const vote = await prisma.approvalVote.findFirstOrThrow({ where: { requestId } });
      expect(vote.reason).toBe("Operational requirement");
    });
  });

  describe("replay and substitution attacks through the API", () => {
    it("a signature for APPROVE cannot be submitted as REJECT", async () => {
      const { requestId } = await createRequest();
      const approveOpts = await options(requestId, approver, "APPROVE");
      const approveSignature = authenticatorFor(approver.id).createAssertion(approveOpts.challenge);

      const relabeled = await submit(requestId, approver, { decision: "REJECT", response: approveSignature });
      expect(relabeled.status).toBe(400);
      expect(await voteCount(requestId)).toBe(0);
    });

    it("a signature for APPROVE cannot be replayed while a REJECT statement is also pending", async () => {
      const { requestId } = await createRequest();
      const approveOpts = await options(requestId, approver, "APPROVE");
      const approveSignature = authenticatorFor(approver.id).createAssertion(approveOpts.challenge);
      const rejectOpts = await options(requestId, approver, "REJECT"); // both statements now pending

      // The APPROVE signature can only ever resolve to the APPROVE statement it signed.
      const res = await submit(requestId, approver, { decision: "REJECT", response: approveSignature });
      expect(res.status).toBe(400);
      expect(await voteCount(requestId)).toBe(0);

      // A signature over the REJECT statement, forged onto the APPROVE challenge
      // by swapping clientDataJSON, doesn't verify either.
      const rejectSignature = authenticatorFor(approver.id).createAssertion(rejectOpts.challenge);
      const spliced = {
        ...rejectSignature,
        response: { ...rejectSignature.response, clientDataJSON: approveSignature.response.clientDataJSON },
      };
      const splicedRes = await submit(requestId, approver, { decision: "REJECT", response: spliced });
      expect(splicedRes.status).toBe(400);
      expect(await voteCount(requestId)).toBe(0);
    });

    it("a signature for request A cannot be used for request B", async () => {
      const a = await createRequest();
      const b = await createRequest();
      const optsA = await options(a.requestId, approver, "APPROVE");
      await options(b.requestId, approver, "APPROVE");
      const signatureForA = authenticatorFor(approver.id).createAssertion(optsA.challenge);

      const res = await submit(b.requestId, approver, { decision: "APPROVE", response: signatureForA });
      expect(res.status).toBe(400);
      expect(await voteCount(b.requestId)).toBe(0);
      // ...and it's still only good for A.
      expect((await submit(a.requestId, approver, { decision: "APPROVE", response: signatureForA })).status).toBe(200);
    });

    it("a signature over one proposal digest cannot approve a modified proposal", async () => {
      const { actionId, requestId } = await createRequest({ block: "B87", section: "S3", window: "03:20-04:05" });
      const opts = await options(requestId, approver, "APPROVE");
      const signature = authenticatorFor(approver.id).createAssertion(opts.challenge);

      // The application role can't rewrite the subject at all...
      await expect(
        prisma.sensitiveAction.update({ where: { id: actionId }, data: { payload: { block: "B87", section: "S3", window: "01:00-06:00" } } }),
      ).rejects.toThrow(/immutable/);

      // ...so simulate a database-owner rewrite of payload AND digest together.
      const tampered = { block: "B87", section: "S3", window: "01:00-06:00" };
      await prisma.$transaction(async (tx) => {
        await tx.$executeRawUnsafe("SET LOCAL session_replication_role = replica");
        await tx.$executeRaw`UPDATE "SensitiveAction" SET "payload" = ${JSON.stringify(tampered)}::jsonb, "payloadDigest" = ${computeSubjectDigest(actionType, tampered)} WHERE "id" = ${actionId}`;
      });

      const res = await submit(requestId, approver, { decision: "APPROVE", response: signature });
      expect(res.status).toBe(409);
      expect(await voteCount(requestId)).toBe(0);
    });

    it("a payload rewritten without updating the digest is also refused", async () => {
      const { actionId, requestId } = await createRequest({ amount: 10 });
      const opts = await options(requestId, approver, "APPROVE");
      const signature = authenticatorFor(approver.id).createAssertion(opts.challenge);
      await prisma.$transaction(async (tx) => {
        await tx.$executeRawUnsafe("SET LOCAL session_replication_role = replica");
        await tx.$executeRaw`UPDATE "SensitiveAction" SET "payload" = '{"amount": 10000}'::jsonb WHERE "id" = ${actionId}`;
      });
      expect((await submit(requestId, approver, { decision: "APPROVE", response: signature })).status).toBe(409);
      expect(await voteCount(requestId)).toBe(0);
    });

    it("another approver's signature over the same statement is rejected", async () => {
      const { requestId } = await createRequest();
      const opts = await options(requestId, approver, "APPROVE");
      const foreign = authenticatorFor(approver2.id).createAssertion(opts.challenge);
      const res = await submit(requestId, approver, { decision: "APPROVE", response: foreign });
      expect(res.status).toBe(400);
      expect(await voteCount(requestId)).toBe(0);
    });

    it("a submitted reason different from the signed reason is rejected", async () => {
      const { requestId } = await createRequest();
      const opts = await options(requestId, approver, "REJECT", "Unsafe window");
      const signature = authenticatorFor(approver.id).createAssertion(opts.challenge);
      const res = await submit(requestId, approver, { decision: "REJECT", reason: "Approved really", response: signature });
      expect(res.status).toBe(400);
      expect(await voteCount(requestId)).toBe(0);
    });

    it("an assertion without user verification is rejected", async () => {
      const { requestId } = await createRequest();
      const res = await castVote(requestId, noUvApprover, "APPROVE");
      expect(res.status).toBe(400);
      expect(await voteCount(requestId)).toBe(0);
    });

    it("a pending statement is single-use: the same signature can't be submitted twice", async () => {
      const { requestId } = await createRequest();
      const opts = await options(requestId, approver, "APPROVE");
      const signature = authenticatorFor(approver.id).createAssertion(opts.challenge);
      expect((await submit(requestId, approver, { decision: "APPROVE", response: signature })).status).toBe(200);
      expect((await submit(requestId, approver, { decision: "APPROVE", response: signature })).status).toBe(400);
      expect(await voteCount(requestId)).toBe(1);
    });

    it("an action created before subject digests existed cannot be voted on", async () => {
      const policy = await prisma.approvalPolicy.findUniqueOrThrow({ where: { actionType } });
      const legacy = await prisma.sensitiveAction.create({ data: { type: actionType, payload: { legacy: true }, requestedById: requester.id } });
      // A real snapshot, so the refusal below can only come from the missing digest.
      const request = await createApprovalRequestWithSnapshot({ actionId: legacy.id, policyId: policy.id, expiresAt: new Date(Date.now() + 60_000) });
      const res = await apiRequest(`/approvals/${request.id}/options`, { method: "POST", token: approver.token, body: { decision: "APPROVE" } });
      expect(res.status).toBe(409);
    });
  });

  describe("tampering with any signed field breaks stored-evidence verification", () => {
    let vote: StoredVoteEvidence;
    let action: { id: string; type: string; payload: unknown; payloadDigest: string | null };

    beforeAll(async () => {
      const created = await createRequest({ block: "B9", reason: "evidence" });
      const res = await castVote(created.requestId, approver, "REJECT", "Track occupied");
      expect(res.status).toBe(200);
      vote = await prisma.approvalVote.findFirstOrThrow({ where: { requestId: created.requestId } });
      action = await prisma.sensitiveAction.findUniqueOrThrow({ where: { id: created.actionId } });
      expect((await verifyStoredVoteEvidence(vote, action, expected)).valid).toBe(true);
    });

    function withStatement(mutate: (s: Record<string, unknown>) => void): StoredVoteEvidence {
      const statement = JSON.parse(vote.signedStatement!) as Record<string, unknown>;
      mutate(statement);
      const serialized = canonicalJson(statement);
      return { ...vote, signedStatement: serialized, statementHash: createHash("sha256").update(serialized).digest("hex") };
    }

    function flipByte(b64: string, index = 10): string {
      const bytes = Buffer.from(isoBase64URL.toBuffer(b64));
      bytes[index] ^= 0x01;
      return isoBase64URL.fromBuffer(bytes);
    }

    const cases: [string, () => StoredVoteEvidence | Promise<StoredVoteEvidence>, (() => typeof action)?][] = [
      ["recorded decision (REJECT -> APPROVE)", () => ({ ...vote, decision: "APPROVE" })],
      ["recorded reason", () => ({ ...vote, reason: "Looks fine" })],
      ["recorded request id", () => ({ ...vote, requestId: "00000000-0000-0000-0000-000000000000" })],
      ["recorded approver id", () => ({ ...vote, approverId: requester.id })],
      ["signed statement decision (rehashed)", () => withStatement((s) => { s.decision = "APPROVE"; })],
      ["signed statement request id (rehashed)", () => withStatement((s) => { s.requestId = "another-request"; })],
      ["signed statement subject digest (rehashed)", () => withStatement((s) => { s.subjectDigest = `sha256:${"0".repeat(64)}`; })],
      ["signed statement approver (rehashed)", () => withStatement((s) => { s.approverId = requester.id; })],
      ["signed statement nonce (rehashed)", () => withStatement((s) => { s.nonce = "A".repeat(43); })],
      ["signed statement issuedAt (rehashed)", () => withStatement((s) => { s.issuedAt = new Date(0).toISOString(); })],
      ["statement hash", () => ({ ...vote, statementHash: "0".repeat(64) })],
      ["non-canonical statement bytes", () => ({ ...vote, signedStatement: vote.signedStatement!.replace("{", "{ ") })],
      ["clientDataJSON", () => ({ ...vote, clientDataJSON: flipByte(vote.clientDataJSON!, 20) })],
      ["authenticatorData", () => ({ ...vote, authenticatorData: flipByte(vote.authenticatorData!, 33) })],
      ["signature", () => ({ ...vote, signature: flipByte(vote.signature, 12) })],
      ["credential public key (swapped for another key)", () => ({ ...vote, credentialPublicKey: new SoftAuthenticator().publicKeyBase64url })],
      ["action payload", () => vote, () => ({ ...action, payload: { block: "B9", reason: "tampered" } })],
      ["action digest", () => vote, () => ({ ...action, payloadDigest: `sha256:${"1".repeat(64)}` })],
    ];

    for (const [field, tamperVote, tamperAction] of cases) {
      it(`detects a tampered ${field}`, async () => {
        const result = await verifyStoredVoteEvidence(await tamperVote(), tamperAction ? tamperAction() : action, expected);
        expect(result.valid).toBe(false);
        expect(result.errors.length).toBeGreaterThan(0);
      });
    }

    it("detects evidence verified against the wrong relying party origin", async () => {
      expect((await verifyStoredVoteEvidence(vote, action, { rpId: env.rpId, origin: "https://evil.example" })).valid).toBe(false);
    });

    it("the database refuses to rewrite a recorded vote", async () => {
      await expect(prisma.approvalVote.updateMany({ where: { statementHash: vote.statementHash }, data: { decision: "APPROVE" } })).rejects.toThrow(
        /not permitted/,
      );
    });
  });
});
