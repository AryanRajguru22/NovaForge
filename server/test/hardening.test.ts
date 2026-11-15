import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { Request, Response } from "express";
import {
  startTestServer,
  stopTestServer,
  apiRequest,
  createUserWithToken,
  addMockPasskey,
  authenticatorFor,
  cleanupUsers,
  cleanupPolicies,
  createApprovalRequestWithSnapshot,
  runSuffix,
} from "./testServer.js";
import { prisma } from "../src/lib/prisma.js";
import { computeSubjectDigest } from "../src/lib/approvalSignature.js";
import { bootstrapFirstAdminInTransaction, BootstrapRefusedError } from "../src/cli/bootstrap-admin.js";
import { MAX_BUCKETS, bucketCount, rateLimit, resetRateLimitBuckets } from "../src/middleware/rateLimit.js";

describe("passkey login options do not reveal which accounts exist", () => {
  const emails = {
    withPasskey: `enum-real-${runSuffix}@example.com`,
    noPasskey: `enum-nokey-${runSuffix}@example.com`,
    unknown: `enum-unknown-${runSuffix}@example.com`,
  };

  beforeAll(async () => {
    await startTestServer();
    await cleanupUsers([emails.withPasskey, emails.noPasskey]);
    const real = await createUserWithToken({ email: emails.withPasskey });
    await addMockPasskey(real.user.id);
    await createUserWithToken({ email: emails.noPasskey });
  });

  afterAll(async () => {
    await cleanupUsers([emails.withPasskey, emails.noPasskey]);
    await stopTestServer();
  });

  const options = (email: string) => apiRequest("/auth/login/options", { method: "POST", body: { email } });

  it("answers 200 with the same shape for a real account, a passkey-less account and an unknown address", async () => {
    const [real, none, unknown] = await Promise.all([options(emails.withPasskey), options(emails.noPasskey), options(emails.unknown)]);
    for (const r of [real, none, unknown]) {
      expect(r.status).toBe(200);
      expect(r.data.allowCredentials).toHaveLength(1);
      expect(typeof r.data.challenge).toBe("string");
      expect(r.data.rpId).toBe(real.data.rpId);
      // F-16: the ceremony asks for user verification, matching what /login/verify enforces.
      expect(r.data.userVerification).toBe("required");
    }
  });

  it("uses a stable decoy credential for unknown addresses, never the real credential id", async () => {
    const a = await options(emails.unknown);
    const b = await options(emails.unknown);
    expect(a.data.allowCredentials[0].id).toBe(b.data.allowCredentials[0].id);
    const real = await options(emails.withPasskey);
    expect(real.data.allowCredentials[0].id).not.toBe(a.data.allowCredentials[0].id);
    const none = await options(emails.noPasskey);
    expect(none.data.allowCredentials[0].id).not.toBe(a.data.allowCredentials[0].id); // decoy is per email
  });

  it("fails verification with one identical message whether the account is unknown, passkey-less, or the signature is wrong", async () => {
    const opts = await options(emails.withPasskey);
    // A valid signature from a different key than the one registered.
    const stranger = await createUserWithToken({ email: `enum-stranger-${runSuffix}@example.com` });
    await addMockPasskey(stranger.user.id);
    const forged = authenticatorFor(stranger.user.id).createAssertion(opts.data.challenge);

    const wrongKey = await apiRequest("/auth/login/verify", { method: "POST", body: { email: emails.withPasskey, response: forged } });

    const unknownOpts = await options(emails.unknown);
    const forgedUnknown = authenticatorFor(stranger.user.id).createAssertion(unknownOpts.data.challenge);
    const unknown = await apiRequest("/auth/login/verify", { method: "POST", body: { email: emails.unknown, response: forgedUnknown } });

    const noKeyOpts = await options(emails.noPasskey);
    const forgedNoKey = authenticatorFor(stranger.user.id).createAssertion(noKeyOpts.data.challenge);
    const noKey = await apiRequest("/auth/login/verify", { method: "POST", body: { email: emails.noPasskey, response: forgedNoKey } });

    expect([wrongKey.status, unknown.status, noKey.status]).toEqual([400, 400, 400]);
    expect(new Set([wrongKey.data.error, unknown.data.error, noKey.data.error]).size).toBe(1);
    await cleanupUsers([`enum-stranger-${runSuffix}@example.com`]);
  });
});

describe("database refuses to change a decided approval", () => {
  const email = `terminal-guard-${runSuffix}@example.com`;
  const actionType = `test:terminal-guard-${runSuffix}`;
  let requesterId: string;
  let policyId: string;

  beforeAll(async () => {
    await cleanupUsers([email]);
    await cleanupPolicies([actionType]);
    requesterId = (await createUserWithToken({ email })).user.id;
    policyId = (
      await prisma.approvalPolicy.create({
        data: { actionType, quorumType: "N_OF_M", minApprovals: 1, eligibleRoles: ["APPROVER"], escalationTimeoutSec: 300 },
      })
    ).id;
  });

  afterAll(async () => {
    await prisma.approvalRequest.deleteMany({ where: { policy: { actionType } } });
    await prisma.sensitiveAction.deleteMany({ where: { requestedById: requesterId } });
    await cleanupPolicies([actionType]);
    await cleanupUsers([email]);
  });

  async function newRequest(n: number) {
    const payload = { n };
    const action = await prisma.sensitiveAction.create({
      data: { type: actionType, payload, payloadDigest: computeSubjectDigest(actionType, payload), requestedById: requesterId },
    });
    const request = await createApprovalRequestWithSnapshot({ actionId: action.id, policyId, expiresAt: new Date(Date.now() + 60_000) });
    return { action, request };
  }

  it("still allows the one legitimate transition, PENDING to a decision", async () => {
    const { action, request } = await newRequest(1);
    await prisma.approvalRequest.update({ where: { id: request.id }, data: { status: "APPROVED" } });
    await prisma.sensitiveAction.update({ where: { id: action.id }, data: { status: "APPROVED" } });
    expect((await prisma.approvalRequest.findUniqueOrThrow({ where: { id: request.id } })).status).toBe("APPROVED");
  });

  for (const from of ["APPROVED", "REJECTED", "EXPIRED", "POSTPONED"] as const) {
    it(`rejects any change out of ${from}, on the request and on the action`, async () => {
      const { action, request } = await newRequest(10);
      await prisma.approvalRequest.update({ where: { id: request.id }, data: { status: from } });
      await prisma.sensitiveAction.update({ where: { id: action.id }, data: { status: from } });
      const other = from === "APPROVED" ? "REJECTED" : "APPROVED";

      await expect(prisma.approvalRequest.update({ where: { id: request.id }, data: { status: other } })).rejects.toThrow(/cannot be changed/);
      await expect(prisma.approvalRequest.update({ where: { id: request.id }, data: { status: "PENDING" } })).rejects.toThrow(/cannot be changed/);
      await expect(prisma.sensitiveAction.update({ where: { id: action.id }, data: { status: other } })).rejects.toThrow(/cannot be changed/);
      await expect(prisma.sensitiveAction.update({ where: { id: action.id }, data: { status: "PENDING" } })).rejects.toThrow(/cannot be changed/);

      expect((await prisma.approvalRequest.findUniqueOrThrow({ where: { id: request.id } })).status).toBe(from);
    });
  }

  it("does not block writes that leave the status unchanged (e.g. extending nothing, touching expiry)", async () => {
    const { request } = await newRequest(20);
    await prisma.approvalRequest.update({ where: { id: request.id }, data: { status: "EXPIRED" } });
    await prisma.approvalRequest.update({ where: { id: request.id }, data: { status: "EXPIRED", expiresAt: new Date() } });
  });
});

describe("in-memory rate limiter is memory-bounded", () => {
  function run(limit: ReturnType<typeof rateLimit>, ip: string): { status: number; nexted: boolean } {
    let nexted = false;
    const res = { setHeader() {}, status(code: number) { this.code = code; return this; }, json() { return this; }, code: 200 } as unknown as Response & { code: number };
    limit({ ip, baseUrl: "/t", path: "/x", body: {} } as unknown as Request, res, () => { nexted = true; });
    return { status: res.code, nexted };
  }

  it("never holds more than MAX_BUCKETS entries however many distinct identities arrive", () => {
    resetRateLimitBuckets();
    const limit = rateLimit({ max: 5, windowMs: 60_000, identity: (req) => String((req as any).n) });
    for (let i = 0; i < MAX_BUCKETS + 3000; i++) {
      let nexted = false;
      limit({ ip: "10.0.0.1", baseUrl: "/t", path: "/x", n: i } as unknown as Request, { setHeader() {}, status() { return this; }, json() {} } as unknown as Response, () => { nexted = true; });
      expect(nexted).toBe(true);
    }
    expect(bucketCount()).toBeLessThanOrEqual(MAX_BUCKETS);
    resetRateLimitBuckets();
  });

  it("still enforces the limit for a repeated identity", () => {
    resetRateLimitBuckets();
    const limit = rateLimit({ max: 3, windowMs: 60_000 });
    const results = Array.from({ length: 5 }, () => run(limit, "10.0.0.2"));
    expect(results.map((r) => r.nexted)).toEqual([true, true, true, false, false]);
    expect(results[3].status).toBe(429);
    resetRateLimitBuckets();
  });

  it("keeps a bounded key for very long attacker-chosen identities", () => {
    resetRateLimitBuckets();
    const limit = rateLimit({ max: 1, windowMs: 60_000, identity: () => "x".repeat(100_000) });
    expect(run(limit, "10.0.0.3").nexted).toBe(true);
    expect(run(limit, "10.0.0.3").nexted).toBe(false);
    resetRateLimitBuckets();
  });
});

describe("first-administrator bootstrap", () => {
  // Runs inside a transaction that is always rolled back, so it never touches
  // the shared database's real administrators or audit chain.
  const ROLLBACK = new Error("rollback");
  async function inRolledBackTx<T>(fn: (tx: any) => Promise<T>): Promise<T> {
    let out!: T;
    await prisma
      .$transaction(async (tx) => {
        out = await fn(tx);
        throw ROLLBACK;
      }, { timeout: 30_000 })
      .catch((e) => {
        if (e !== ROLLBACK) throw e;
      });
    return out;
  }
  const demoteAll = (tx: any) => tx.user.updateMany({ where: { role: "SUPER_ADMIN" }, data: { status: "DISABLED" } });

  it("creates a SUPER_ADMIN with a single-use hashed enrollment token on an empty installation", async () => {
    const email = `boot-${runSuffix}@example.com`;
    const out = await inRolledBackTx(async (tx) => {
      await demoteAll(tx);
      const r = await bootstrapFirstAdminInTransaction(tx, { email, name: "First Admin" });
      const user = await tx.user.findUnique({ where: { email } });
      const token = await tx.enrollmentToken.findFirst({ where: { userId: user.id } });
      const audit = await tx.auditLog.findMany({ where: { entityId: user.id }, select: { event: true } });
      return { r, user, token, audit };
    });
    expect(out.user.role).toBe("SUPER_ADMIN");
    expect(out.r.token).toMatch(/^nfenr_[A-Za-z0-9_-]{43}$/);
    expect(out.token.tokenHash).not.toContain(out.r.token); // only a hash is stored
    expect(out.token.usedAt).toBeNull();
    expect(out.audit.map((a: any) => a.event)).toEqual(expect.arrayContaining(["USER_CREATED_BY_OPERATOR", "ENROLLMENT_TOKEN_ISSUED"]));
    // Rolled back: nothing leaked into the shared database.
    expect(await prisma.user.findUnique({ where: { email } })).toBeNull();
  });

  it("refuses once an active SUPER_ADMIN exists, so it cannot be reused to escalate", async () => {
    const outcome = await inRolledBackTx(async (tx) => {
      await demoteAll(tx);
      await tx.user.create({ data: { email: `existing-admin-${runSuffix}@example.com`, name: "Existing", role: "SUPER_ADMIN" } });
      return bootstrapFirstAdminInTransaction(tx, { email: `attacker-${runSuffix}@example.com`, name: "Eve" }).then(
        () => "created",
        (e) => e,
      );
    });
    expect(outcome).toBeInstanceOf(BootstrapRefusedError);
    expect(String(outcome.message)).toMatch(/already exists/);
  });

  it("will not promote a disabled account, and requires --name for a new one", async () => {
    const outcome = await inRolledBackTx(async (tx) => {
      await demoteAll(tx);
      const email = `disabled-${runSuffix}@example.com`;
      await tx.user.create({ data: { email, name: "Gone", status: "DISABLED" } });
      const disabled = await bootstrapFirstAdminInTransaction(tx, { email }).catch((e) => e);
      const nameless = await bootstrapFirstAdminInTransaction(tx, { email: `nameless-${runSuffix}@example.com` }).catch((e) => e);
      const invalid = await bootstrapFirstAdminInTransaction(tx, { email: "not-an-email", name: "x" }).catch((e) => e);
      return { disabled, nameless, invalid };
    });
    expect(outcome.disabled).toBeInstanceOf(BootstrapRefusedError);
    expect(outcome.nameless).toBeInstanceOf(BootstrapRefusedError);
    expect(outcome.invalid).toBeInstanceOf(BootstrapRefusedError);
  });
});
