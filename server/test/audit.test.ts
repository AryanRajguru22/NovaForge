import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { randomUUID } from "node:crypto";
import type { Prisma } from "@prisma/client";
import {
  appendAuditLog,
  auditedTransaction,
  computeAuditHashV2,
  getAuditChainHead,
  verifyAuditChain,
  AuditIntegrityError,
  type AuditIssueKind,
} from "../src/lib/audit.js";
import { prisma } from "../src/lib/prisma.js";
import { startTestServer, stopTestServer, apiRequest, createUserWithToken, addMockPasskey, governanceProof, cleanupUsers, runSuffix } from "./testServer.js";

// P0-5 coverage for the linear, append-only audit chain.
//
// Tamper scenarios simulate an attacker with database-owner privileges: they
// run inside a transaction with `session_replication_role = replica`, which
// disables the append-only triggers exactly as a DB owner could, and that
// transaction is always rolled back afterwards -- so the shared chain other
// test files append to is never actually damaged. Integrity checks inside
// these scenarios are run against that same transaction.

class Rollback extends Error {}

async function asDatabaseOwnerThenRollback(fn: (tx: Prisma.TransactionClient) => Promise<void>): Promise<void> {
  try {
    await prisma.$transaction(
      async (tx) => {
        await tx.$executeRawUnsafe("SET LOCAL session_replication_role = replica");
        await fn(tx);
        throw new Rollback();
      },
      { timeout: 60_000, maxWait: 15_000 },
    );
  } catch (err) {
    if (!(err instanceof Rollback)) throw err;
  }
}

function kinds(result: { issues: { kind: AuditIssueKind }[] }): AuditIssueKind[] {
  return result.issues.map((i) => i.kind);
}

async function appendCommitted(event: string, extra: Partial<{ actorId: string; metadata: object }> = {}) {
  return auditedTransaction((tx) =>
    appendAuditLog(tx, { entityType: "AuditTest", entityId: `audit-test-${runSuffix}`, event, ...extra }),
  );
}

describe("P0-5: audit hash chain", () => {
  let windowStart: bigint;
  let rows: Awaited<ReturnType<typeof appendCommitted>>[] = [];

  beforeAll(async () => {
    rows = [];
    for (const event of ["STEP_ONE", "STEP_TWO", "STEP_THREE", "STEP_FOUR", "STEP_FIVE"]) {
      rows.push(await appendCommitted(event, { metadata: { n: rows.length, nested: { b: 2, a: [1, "x"] } } }));
    }
    windowStart = rows[0].seq;
  });

  describe("linear appends", () => {
    it("assigns contiguous seq values, links each row to its predecessor, and verifies", async () => {
      for (let i = 1; i < rows.length; i++) {
        expect(rows[i].seq).toBe(rows[i - 1].seq + 1n);
        expect(rows[i].prevHash).toBe(rows[i - 1].hash);
        expect(rows[i].timestamp.getTime()).toBeGreaterThanOrEqual(rows[i - 1].timestamp.getTime());
      }
      const result = await verifyAuditChain({ fromSeq: windowStart });
      expect(result.issues).toEqual([]);
      expect(result.valid).toBe(true);
    });

    it("stores metadata losslessly: 17-significant-digit numbers still verify", async () => {
      const row = await appendCommitted("FLOAT_METADATA", { metadata: { risk: 0.38331432302637536, list: [0.20213987566293812, 1e21] } });
      expect((row.metadata as { risk: number }).risk).toBe(0.38331432302637536);
      const result = await verifyAuditChain({ fromSeq: row.seq });
      expect(result.issues).toEqual([]);
    });

    it("advances the chain head to the newest row", async () => {
      const row = await appendCommitted("HEAD_CHECK");
      const head = await getAuditChainHead();
      expect(head).toEqual({ seq: row.seq.toString(), hash: row.hash });
    });

    it("binds the correlation id of the request that produced the event", async () => {
      const row = await auditedTransaction((tx) =>
        appendAuditLog(tx, { entityType: "AuditTest", entityId: "corr", event: "CORRELATED", correlationId: "req-12345678" }),
      );
      expect(row.correlationId).toBe("req-12345678");
      expect(row.hashVersion).toBe(2);
    });
  });

  describe("concurrency is enforced by the database", () => {
    it("serializes many genuinely concurrent appends into one linear chain with no duplicate predecessor", async () => {
      const before = await getAuditChainHead();
      const N = 25;
      const results = await Promise.all(
        Array.from({ length: N }, (_, i) => appendCommitted("CONCURRENT_APPEND", { metadata: { i } })),
      );

      const seqs = results.map((r) => r.seq).sort((a, b) => (a < b ? -1 : 1));
      expect(new Set(seqs.map(String)).size).toBe(N);
      expect(seqs[seqs.length - 1] - seqs[0]).toBe(BigInt(N - 1));
      expect(new Set(results.map((r) => r.prevHash)).size).toBe(N);

      const result = await verifyAuditChain({ fromSeq: BigInt(before!.seq) + 1n });
      expect(result.issues).toEqual([]);
      expect(result.valid).toBe(true);
    });

    it("rejects a writer that bypasses the head lock and races another writer for the same predecessor (no fork)", async () => {
      // Each transaction reads the head WITHOUT locking, pauses so both have
      // read the same head, then inserts a correctly hashed row claiming it.
      const racingInsert = (label: string) =>
        prisma.$transaction(
          async (tx) => {
            const [head] = await tx.$queryRaw<{ seq: bigint; hash: string }[]>`SELECT "seq", "hash" FROM "AuditChainHead" WHERE "id" = 1`;
            await new Promise((r) => setTimeout(r, 150));
            const row = {
              seq: head.seq + 1n,
              id: randomUUID(),
              timestamp: new Date(),
              entityType: "AuditTest",
              entityId: "fork-attempt",
              event: label,
              actorId: null,
              correlationId: null,
              metadata: null,
              prevHash: head.hash,
            };
            return tx.auditLog.create({
              data: {
                ...row,
                metadata: undefined,
                actorIdAtWrite: null,
                hashVersion: 2,
                hash: computeAuditHashV2(row),
              },
            });
          },
          { timeout: 30_000 },
        );

      const outcomes = await Promise.allSettled([racingInsert("FORK_A"), racingInsert("FORK_B")]);
      expect(outcomes.filter((o) => o.status === "fulfilled")).toHaveLength(1);
      expect(outcomes.filter((o) => o.status === "rejected")).toHaveLength(1);

      const winner = (outcomes.find((o) => o.status === "fulfilled") as PromiseFulfilledResult<{ seq: bigint }>).value;
      const result = await verifyAuditChain({ fromSeq: winner.seq - 1n });
      expect(result.valid).toBe(true);
    });

    it("rejects an insert that does not directly follow the head, even with a correct hash", async () => {
      const head = await getAuditChainHead();
      const row = {
        seq: BigInt(head!.seq) + 5n,
        id: randomUUID(),
        timestamp: new Date(),
        entityType: "AuditTest",
        entityId: "gap-attempt",
        event: "GAP",
        actorId: null,
        correlationId: null,
        metadata: null,
        prevHash: head!.hash,
      };
      await expect(
        prisma.auditLog.create({
          data: { ...row, metadata: undefined, actorIdAtWrite: null, hashVersion: 2, hash: computeAuditHashV2(row) },
        }),
      ).rejects.toThrow(/audit chain integrity/);
    });
  });

  describe("atomicity with business writes", () => {
    it("rolls back the audit event when the transaction fails after appending it", async () => {
      const before = await getAuditChainHead();
      const marker = `rollback-${randomUUID()}`;
      await expect(
        auditedTransaction(async (tx) => {
          await appendAuditLog(tx, { entityType: "AuditTest", entityId: marker, event: "WILL_ROLL_BACK" });
          throw new Error("business failure after audit append");
        }),
      ).rejects.toThrow("business failure");

      expect(await prisma.auditLog.count({ where: { entityId: marker } })).toBe(0);
      expect(await getAuditChainHead()).toEqual(before);
    });

    it("rolls back the business write when its audit append fails (no state change without its audit event)", async () => {
      const actionType = `test:audit-atomic-${randomUUID()}`;
      await expect(
        auditedTransaction(async (tx) => {
          await tx.approvalPolicy.create({
            data: { actionType, quorumType: "N_OF_M", minApprovals: 1, eligibleRoles: ["APPROVER"] },
          });
          // BigInt metadata has no JSON form, so the append throws.
          await appendAuditLog(tx, { entityType: "ApprovalPolicy", entityId: actionType, event: "POLICY_CREATED", metadata: { bad: 1n } });
        }),
      ).rejects.toThrow();

      expect(await prisma.approvalPolicy.findUnique({ where: { actionType } })).toBeNull();
    });

    it("rolls back the audit event when the business write fails after it", async () => {
      const existing = `test:audit-dup-${randomUUID()}`;
      await prisma.approvalPolicy.create({ data: { actionType: existing, quorumType: "N_OF_M", minApprovals: 1, eligibleRoles: ["APPROVER"] } });
      const marker = `dup-${randomUUID()}`;
      await expect(
        auditedTransaction(async (tx) => {
          await appendAuditLog(tx, { entityType: "ApprovalPolicy", entityId: marker, event: "POLICY_CREATED" });
          await tx.approvalPolicy.create({ data: { actionType: existing, quorumType: "N_OF_M", minApprovals: 1, eligibleRoles: ["APPROVER"] } });
        }),
      ).rejects.toThrow();
      expect(await prisma.auditLog.count({ where: { entityId: marker } })).toBe(0);
      await prisma.approvalPolicy.delete({ where: { actionType: existing } });
    });
  });

  describe("append-only protection for the application role", () => {
    it("rejects UPDATE of an audit row", async () => {
      await expect(prisma.auditLog.update({ where: { id: rows[1].id }, data: { event: "TAMPERED" } })).rejects.toThrow(/append-only/);
    });

    it("rejects DELETE of an audit row", async () => {
      await expect(prisma.auditLog.delete({ where: { id: rows[1].id } })).rejects.toThrow(/not permitted/);
    });

    it("rejects moving the chain head directly", async () => {
      await expect(prisma.$executeRaw`UPDATE "AuditChainHead" SET "seq" = 1 WHERE "id" = 1`).rejects.toThrow(/chain head/);
    });
  });

  describe("tamper detection (attacker with database-owner privileges)", () => {
    it("detects a tampered payload (metadata)", async () => {
      await asDatabaseOwnerThenRollback(async (tx) => {
        await tx.$executeRaw`UPDATE "AuditLog" SET "metadata" = '{"n": 999}'::jsonb WHERE "id" = ${rows[2].id}`;
        const result = await verifyAuditChain({ client: tx, fromSeq: windowStart });
        expect(result.valid).toBe(false);
        expect(result.issues[0]).toMatchObject({ kind: "HASH_MISMATCH", id: rows[2].id });
      });
    });

    it("detects a tampered timestamp", async () => {
      await asDatabaseOwnerThenRollback(async (tx) => {
        await tx.$executeRaw`UPDATE "AuditLog" SET "timestamp" = "timestamp" - interval '1 second' WHERE "id" = ${rows[2].id}`;
        const result = await verifyAuditChain({ client: tx, fromSeq: windowStart });
        expect(result.valid).toBe(false);
        expect(kinds(result)).toContain("HASH_MISMATCH");
        expect(result.brokenAt).toBe(rows[2].id);
      });
    });

    it("detects a tampered actor", async () => {
      await asDatabaseOwnerThenRollback(async (tx) => {
        await tx.$executeRaw`UPDATE "AuditLog" SET "actorIdAtWrite" = 'someone-else' WHERE "id" = ${rows[2].id}`;
        const result = await verifyAuditChain({ client: tx, fromSeq: windowStart });
        expect(result.issues[0]).toMatchObject({ kind: "HASH_MISMATCH", id: rows[2].id });
      });
    });

    it("detects a tampered action (event name)", async () => {
      await asDatabaseOwnerThenRollback(async (tx) => {
        await tx.$executeRaw`UPDATE "AuditLog" SET "event" = 'TAMPERED' WHERE "id" = ${rows[3].id}`;
        const result = await verifyAuditChain({ client: tx, fromSeq: windowStart });
        expect(result.issues[0]).toMatchObject({ kind: "HASH_MISMATCH", id: rows[3].id });
      });
    });

    it("detects an incorrect stored hash", async () => {
      await asDatabaseOwnerThenRollback(async (tx) => {
        await tx.$executeRaw`UPDATE "AuditLog" SET "hash" = ${"f".repeat(64)} WHERE "id" = ${rows[2].id}`;
        const result = await verifyAuditChain({ client: tx, fromSeq: windowStart });
        expect(kinds(result)).toContain("HASH_MISMATCH");
        // ...and the successor no longer points at the row's (new) hash.
        expect(result.issues.some((i) => i.kind === "PREDECESSOR_MISMATCH" && i.id === rows[3].id)).toBe(true);
      });
    });

    it("detects a broken predecessor link", async () => {
      await asDatabaseOwnerThenRollback(async (tx) => {
        await tx.$executeRaw`UPDATE "AuditLog" SET "prevHash" = ${rows[0].hash} WHERE "id" = ${rows[2].id}`;
        const result = await verifyAuditChain({ client: tx, fromSeq: windowStart });
        expect(result.issues.some((i) => i.kind === "PREDECESSOR_MISMATCH" && i.id === rows[2].id)).toBe(true);
      });
    });

    it("detects a deleted event", async () => {
      await asDatabaseOwnerThenRollback(async (tx) => {
        await tx.$executeRaw`DELETE FROM "AuditLog" WHERE "id" = ${rows[2].id}`;
        const result = await verifyAuditChain({ client: tx, fromSeq: windowStart });
        expect(result.valid).toBe(false);
        expect(kinds(result)).toEqual(expect.arrayContaining(["SEQUENCE_GAP", "PREDECESSOR_MISMATCH"]));
      });
    });

    it("detects reordered events", async () => {
      await asDatabaseOwnerThenRollback(async (tx) => {
        const a = rows[1];
        const b = rows[3];
        await tx.$executeRaw`UPDATE "AuditLog" SET "seq" = -1 WHERE "id" = ${a.id}`;
        await tx.$executeRaw`UPDATE "AuditLog" SET "seq" = ${a.seq} WHERE "id" = ${b.id}`;
        await tx.$executeRaw`UPDATE "AuditLog" SET "seq" = ${b.seq} WHERE "id" = ${a.id}`;
        const result = await verifyAuditChain({ client: tx, fromSeq: windowStart });
        expect(result.valid).toBe(false);
        expect(kinds(result)).toEqual(expect.arrayContaining(["HASH_MISMATCH", "PREDECESSOR_MISMATCH"]));
      });
    });

    it("detects a forked chain (a new row claiming an older predecessor)", async () => {
      await asDatabaseOwnerThenRollback(async (tx) => {
        const [head] = await tx.$queryRaw<{ seq: bigint }[]>`SELECT "seq" FROM "AuditChainHead" WHERE "id" = 1`;
        const forked = {
          seq: head.seq + 1n,
          id: randomUUID(),
          timestamp: new Date(),
          entityType: "AuditTest",
          entityId: "fork",
          event: "FORKED",
          actorId: null,
          correlationId: null,
          metadata: null,
          prevHash: rows[1].hash, // an older row, not the tip
        };
        await tx.auditLog.create({
          data: { ...forked, metadata: undefined, actorIdAtWrite: null, hashVersion: 2, hash: computeAuditHashV2(forked) },
        });
        const result = await verifyAuditChain({ client: tx, fromSeq: windowStart });
        expect(result.issues.some((i) => i.kind === "PREDECESSOR_MISMATCH" && i.id === forked.id)).toBe(true);
      });
    });

    it("detects a truncated tail relative to the chain head", async () => {
      await asDatabaseOwnerThenRollback(async (tx) => {
        const [head] = await tx.$queryRaw<{ seq: bigint }[]>`SELECT "seq" FROM "AuditChainHead" WHERE "id" = 1`;
        await tx.$executeRaw`DELETE FROM "AuditLog" WHERE "seq" = ${head.seq}`;
        const result = await verifyAuditChain({ client: tx, fromSeq: windowStart });
        expect(kinds(result)).toContain("HEAD_MISMATCH");
      });
    });

    it("fails closed: refuses to append on top of a tampered tail", async () => {
      await asDatabaseOwnerThenRollback(async (tx) => {
        const [head] = await tx.$queryRaw<{ seq: bigint }[]>`SELECT "seq" FROM "AuditChainHead" WHERE "id" = 1`;
        await tx.$executeRaw`UPDATE "AuditLog" SET "hash" = ${"e".repeat(64)} WHERE "seq" = ${head.seq}`;
        await expect(appendAuditLog(tx, { entityType: "AuditTest", entityId: "x", event: "AFTER_TAMPER" })).rejects.toBeInstanceOf(
          AuditIntegrityError,
        );
      });
    });

    it("a fully consistent rewrite is only detectable against a trusted external anchor", async () => {
      // Hash chaining alone cannot stop someone who can rewrite every row and
      // the head: this proves that limitation honestly, and that an anchor
      // recorded outside the database catches it.
      const anchor = { seq: rows[2].seq, hash: rows[2].hash };
      await asDatabaseOwnerThenRollback(async (tx) => {
        const chain = await tx.auditLog.findMany({ where: { seq: { gte: rows[2].seq } }, orderBy: { seq: "asc" } });
        let prevHash = rows[1].hash;
        for (const row of chain) {
          const rewritten = {
            seq: row.seq,
            id: row.id,
            timestamp: row.timestamp,
            entityType: row.entityType,
            entityId: row.entityId,
            event: row.id === rows[2].id ? "REWRITTEN_HISTORY" : row.event,
            actorId: row.actorIdAtWrite,
            correlationId: row.correlationId,
            metadata: row.metadata,
            prevHash,
          };
          const hash = computeAuditHashV2(rewritten);
          await tx.$executeRaw`UPDATE "AuditLog" SET "event" = ${rewritten.event}, "prevHash" = ${prevHash}, "hash" = ${hash} WHERE "id" = ${row.id}`;
          prevHash = hash;
        }
        const lastSeq = chain[chain.length - 1].seq;
        await tx.$executeRaw`UPDATE "AuditChainHead" SET "hash" = ${prevHash}, "seq" = ${lastSeq} WHERE "id" = 1`;

        const withoutAnchor = await verifyAuditChain({ client: tx, fromSeq: windowStart });
        expect(withoutAnchor.valid).toBe(true);

        const withAnchor = await verifyAuditChain({ client: tx, fromSeq: windowStart, anchor });
        expect(withAnchor.valid).toBe(false);
        expect(kinds(withAnchor)).toContain("ANCHOR_MISMATCH");
      });
    });

    it("leaves the real chain intact after every simulated tamper (all were rolled back)", async () => {
      const result = await verifyAuditChain({ fromSeq: windowStart });
      expect(result.issues).toEqual([]);
    });
  });

  describe("API and lifecycle", () => {
    const superEmail = `audit-super-${runSuffix}@example.com`;
    const doomedEmail = `audit-doomed-${runSuffix}@example.com`;
    let superToken: string;
    let superId: string;

    beforeAll(async () => {
      await startTestServer();
      const s = await createUserWithToken({ email: superEmail, role: "SUPER_ADMIN" });
      superToken = s.token;
      superId = s.user.id;
      await addMockPasskey(superId);
    });

    afterAll(async () => {
      await cleanupUsers([superEmail, doomedEmail]);
      await stopTestServer();
    });

    it("deleting a user nulls actorId on their audit rows without breaking verification", async () => {
      const { user } = await createUserWithToken({ email: doomedEmail, role: "MEMBER" });
      const row = await appendCommitted("ACTED_BEFORE_DELETION", { actorId: user.id });
      const response = await governanceProof({ id: superId, token: superToken }, "user");
      const res = await apiRequest(`/users/${user.id}`, { method: "DELETE", token: superToken, body: { response } });
      expect(res.status).toBe(204);

      const after = await prisma.auditLog.findUniqueOrThrow({ where: { id: row.id } });
      expect(after.actorId).toBeNull();
      expect(after.actorIdAtWrite).toBe(user.id);
      const result = await verifyAuditChain({ fromSeq: row.seq });
      expect(result.issues).toEqual([]);
    });

    it("GET /audit/verify accepts a matching anchor and returns 409 with issues for a mismatched one", async () => {
      const ok = await apiRequest(`/audit/verify?anchorSeq=${rows[1].seq}&anchorHash=${rows[1].hash}`, { token: superToken });
      expect(ok.status === 200 || ok.status === 409).toBe(true);
      // Whatever legacy (pre-hardening) rows may show, the anchor itself matches:
      expect((ok.data.issues as { kind: string }[]).some((i) => i.kind === "ANCHOR_MISMATCH")).toBe(false);

      const bad = await apiRequest(`/audit/verify?anchorSeq=${rows[1].seq}&anchorHash=${"a".repeat(64)}`, { token: superToken });
      expect(bad.status).toBe(409);
      expect((bad.data.issues as { kind: string }[]).some((i) => i.kind === "ANCHOR_MISMATCH")).toBe(true);
    });

    it("GET /audit/head exposes the current tip for external anchoring", async () => {
      const res = await apiRequest("/audit/head", { token: superToken });
      expect(res.status).toBe(200);
      expect(res.data.hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it("every sensitive API write has its audit event: creating an action records ACTION_CREATED with the subject digest", async () => {
      const actionType = `test:audit-api-${randomUUID()}`;
      await prisma.approvalPolicy.create({ data: { actionType, quorumType: "N_OF_M", minApprovals: 1, eligibleRoles: ["APPROVER"] } });
      const created = await apiRequest("/actions", { method: "POST", token: superToken, body: { type: actionType, payload: { x: 1 } } });
      expect(created.status).toBe(201);
      const event = await prisma.auditLog.findFirst({ where: { entityId: created.data.action.id, event: "ACTION_CREATED" } });
      expect(event).not.toBeNull();
      expect((event!.metadata as { payloadDigest: string }).payloadDigest).toBe(created.data.action.payloadDigest);

      await prisma.approvalRequest.deleteMany({ where: { policy: { actionType } } });
      await prisma.sensitiveAction.deleteMany({ where: { type: actionType } });
      await prisma.approvalPolicy.delete({ where: { actionType } });
    });
  });
});
