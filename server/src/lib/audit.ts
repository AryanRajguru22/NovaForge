import { createHash, randomUUID } from "node:crypto";
import { Prisma, type PrismaClient } from "@prisma/client";
import { prisma } from "./prisma.js";
import { canonicalJson, sha256Hex, toJsonValue } from "./canonicalJson.js";
import { getCorrelationId } from "./requestContext.js";

// Tamper-evident, linear, append-only audit chain.
//
// Concurrency and atomicity are handled by the database, not by test
// scheduling:
//   * appendAuditLog must be called with a transaction client, inside the
//     same transaction as the business write it records. If either fails,
//     both roll back -- a sensitive state change can never commit without its
//     audit event, and an audit event can never describe a change that didn't
//     happen.
//   * The single AuditChainHead row is locked FOR UPDATE before the next seq
//     and prevHash are chosen, so concurrent writers queue instead of reading
//     the same predecessor. The lock is released on commit or rollback.
//   * A BEFORE INSERT trigger independently re-checks seq = head.seq + 1 and
//     prevHash = head.hash, and an AFTER INSERT trigger advances the head, so
//     even a writer that bypasses this module can't fork the chain.
//   * Rows are append-only (UPDATE/DELETE/TRUNCATE rejected by triggers).
//
// What this does NOT do: a database owner who disables triggers can rewrite
// rows and recompute every hash consistently. Hash chaining makes that
// *detectable* only relative to a trusted reference kept outside the database
// -- an exported chain head (GET /audit/head) passed back as `anchor` to
// verifyAuditChain. No secret is involved: hashing provides tamper evidence,
// not authorization.

export const GENESIS_HASH = "0".repeat(64);
export const CURRENT_HASH_VERSION = 2;

type Db = PrismaClient | Prisma.TransactionClient;

export class AuditIntegrityError extends Error {}

export interface AuditEntryInput {
  entityType: string;
  entityId: string;
  event: string;
  actorId?: string | null;
  metadata?: object | null;
  correlationId?: string | null;
}

interface HashableRowV2 {
  seq: bigint;
  id: string;
  timestamp: Date;
  entityType: string;
  entityId: string;
  event: string;
  actorId: string | null;
  correlationId: string | null;
  metadata: unknown;
  prevHash: string;
}

/** The v2 hash input binds ordering (seq), identity (id), time, the event
 * itself, the actor, correlation, metadata, and the predecessor. */
export function computeAuditHashV2(row: HashableRowV2): string {
  return sha256Hex(
    canonicalJson({
      v: 2,
      seq: row.seq.toString(),
      id: row.id,
      timestamp: row.timestamp.toISOString(),
      entityType: row.entityType,
      entityId: row.entityId,
      event: row.event,
      actorId: row.actorId,
      correlationId: row.correlationId,
      metadata: row.metadata ?? null,
      prevHash: row.prevHash,
    }),
  );
}

// Legacy (hashVersion 1) formula, kept only to verify rows written before
// this redesign. It covers neither seq nor timestamp.
function legacyCanonicalStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (typeof (value as { toJSON?: unknown }).toJSON === "function") {
    return legacyCanonicalStringify((value as { toJSON: () => unknown }).toJSON());
  }
  if (Array.isArray(value)) return `[${value.map((v) => legacyCanonicalStringify(v) ?? "null").join(",")}]`;
  const entries = Object.keys(value as Record<string, unknown>)
    .sort()
    .map((key) => [key, legacyCanonicalStringify((value as Record<string, unknown>)[key])] as const)
    .filter((pair): pair is [string, string] => pair[1] !== undefined)
    .map(([key, val]) => `${JSON.stringify(key)}:${val}`);
  return `{${entries.join(",")}}`;
}

function computeAuditHashV1(prevHash: string | null, payload: object): string {
  return createHash("sha256").update(legacyCanonicalStringify({ prevHash, payload })).digest("hex");
}

/**
 * Runs `fn` in a transaction sized for audited writes: audit appends
 * serialize on the chain head, so a transaction may briefly queue behind
 * other writers.
 */
export function auditedTransaction<T>(fn: (tx: Prisma.TransactionClient) => Promise<T>): Promise<T> {
  return prisma.$transaction(fn, { maxWait: 15_000, timeout: 30_000 });
}

/**
 * Appends one audit event inside the caller's transaction. Fails closed: if
 * the chain tip no longer matches the recorded head (a deleted or rewritten
 * tail), it throws AuditIntegrityError and the caller's whole transaction
 * rolls back instead of extending a chain that is already broken.
 */
export async function appendAuditLog(tx: Prisma.TransactionClient, entry: AuditEntryInput) {
  const [head] = await tx.$queryRaw<{ seq: bigint; hash: string }[]>`
    SELECT "seq", "hash" FROM "AuditChainHead" WHERE "id" = 1 FOR UPDATE`;
  if (!head) throw new AuditIntegrityError("Audit chain head is missing");

  let floorTimestamp: Date | null = null;
  if (head.seq > 0n) {
    const tip = await tx.auditLog.findUnique({ where: { seq: head.seq }, select: { hash: true, timestamp: true } });
    if (!tip || tip.hash !== head.hash) {
      throw new AuditIntegrityError(`Audit chain tip at seq ${head.seq} does not match the chain head; refusing to append`);
    }
    floorTimestamp = tip.timestamp;
  } else if (head.hash !== GENESIS_HASH) {
    throw new AuditIntegrityError("Empty audit chain has a non-genesis head; refusing to append");
  }

  // Timestamps are non-decreasing in seq order by construction (clamped to
  // the tip's under the head lock), so verification can treat a regression
  // as evidence of reordering.
  const now = new Date();
  const timestamp = floorTimestamp && floorTimestamp > now ? floorTimestamp : now;
  const actorId = entry.actorId ?? null;
  const metadata = entry.metadata == null ? null : toJsonValue<object>(entry.metadata);
  const correlationId = entry.correlationId ?? getCorrelationId() ?? null;
  const row: HashableRowV2 = {
    seq: head.seq + 1n,
    id: randomUUID(),
    timestamp,
    entityType: entry.entityType,
    entityId: entry.entityId,
    event: entry.event,
    actorId,
    correlationId,
    metadata,
    prevHash: head.hash,
  };

  const hash = computeAuditHashV2(row);

  // Raw INSERT with an explicit ::jsonb cast of the canonical text, not
  // Prisma's Json write path: Prisma 5 serializes JSON numbers with only 16
  // significant digits, silently changing some doubles (0.38331432302637536
  // is stored as 0.3833143230263754), which would make the stored row hash
  // differently from what was written. Postgres parses the text exactly.
  // The column is `timestamp without time zone` holding UTC (Prisma's
  // convention); convert explicitly so the database session's TimeZone
  // setting can never shift the stored instant away from the hashed one.
  const metadataText = metadata === null ? null : canonicalJson(metadata);
  await tx.$executeRaw`
    INSERT INTO "AuditLog"
      ("id", "seq", "hashVersion", "timestamp", "entityType", "entityId", "event",
       "actorId", "actorIdAtWrite", "metadata", "correlationId", "prevHash", "hash")
    VALUES
      (${row.id}, ${row.seq}, ${CURRENT_HASH_VERSION}, (${timestamp.toISOString()}::timestamptz AT TIME ZONE 'UTC'),
       ${row.entityType}, ${row.entityId}, ${row.event},
       ${actorId}, ${actorId}, ${metadataText}::jsonb, ${correlationId}, ${row.prevHash}, ${hash})`;

  // Fail closed unless the row exactly as stored reproduces its hash.
  const stored = await tx.auditLog.findUniqueOrThrow({ where: { id: row.id } });
  const storedHash = computeAuditHashV2({
    seq: stored.seq,
    id: stored.id,
    timestamp: stored.timestamp,
    entityType: stored.entityType,
    entityId: stored.entityId,
    event: stored.event,
    actorId: stored.actorIdAtWrite,
    correlationId: stored.correlationId,
    metadata: stored.metadata,
    prevHash: stored.prevHash ?? "",
  });
  if (storedHash !== stored.hash) {
    throw new AuditIntegrityError(`Audit row seq ${stored.seq} does not reproduce its hash as stored; refusing to commit`);
  }
  return stored;
}

export type AuditIssueKind =
  | "HASH_MISMATCH"
  | "PREDECESSOR_MISMATCH"
  | "SEQUENCE_GAP"
  | "TIMESTAMP_REGRESSION"
  | "UNKNOWN_HASH_VERSION"
  | "HEAD_MISMATCH"
  | "ANCHOR_MISMATCH";

export interface AuditIssue {
  kind: AuditIssueKind;
  seq: string;
  id?: string;
  detail: string;
}

export interface AuditVerificationResult {
  valid: boolean;
  checkedRows: number;
  fromSeq: string;
  lastSeq: string | null;
  head: { seq: string; hash: string } | null;
  issues: AuditIssue[];
  /** id of the first row found invalid (kept for API compatibility). */
  brokenAt?: string;
}

export interface VerifyAuditChainOptions {
  /** Verify from this seq to the tip (default 1 = whole chain). */
  fromSeq?: bigint;
  /** A trusted, externally stored chain head the chain must still contain. */
  anchor?: { seq: bigint; hash: string };
  /** Run against a specific client/transaction (default: a repeatable-read snapshot). */
  client?: Db;
  batchSize?: number;
}

const MAX_REPORTED_ISSUES = 100;

/**
 * Walks the chain in seq order and reports every integrity violation it can
 * see: modified rows (hash mismatch), deleted rows (sequence gap / predecessor
 * mismatch / head mismatch), reordered rows (hash mismatch -- seq is hashed --
 * and timestamp regression), injected or forked rows (predecessor mismatch),
 * and a truncated or rewritten tail relative to the head or a trusted anchor.
 * It never repairs anything.
 */
export async function verifyAuditChain(opts: VerifyAuditChainOptions = {}): Promise<AuditVerificationResult> {
  if (opts.client) return verifyWith(opts.client, opts);
  // A single snapshot so appends committing mid-walk can't look like a
  // head mismatch.
  return prisma.$transaction((tx) => verifyWith(tx, opts), {
    isolationLevel: Prisma.TransactionIsolationLevel.RepeatableRead,
    maxWait: 15_000,
    timeout: 120_000,
  });
}

async function verifyWith(db: Db, opts: VerifyAuditChainOptions): Promise<AuditVerificationResult> {
  const fromSeq = opts.fromSeq && opts.fromSeq > 1n ? opts.fromSeq : 1n;
  const batchSize = opts.batchSize ?? 1000;
  const issues: AuditIssue[] = [];
  const report = (issue: AuditIssue) => {
    if (issues.length < MAX_REPORTED_ISSUES) issues.push(issue);
  };

  const [headRow] = await db.$queryRaw<{ seq: bigint; hash: string }[]>`SELECT "seq", "hash" FROM "AuditChainHead" WHERE "id" = 1`;
  const head = headRow ? { seq: headRow.seq, hash: headRow.hash } : null;
  if (!head) report({ kind: "HEAD_MISMATCH", seq: "0", detail: "Audit chain head row is missing" });

  let expectedPrev: string | null = GENESIS_HASH;
  let prevTimestamp: Date | null = null;
  let expectedSeq = fromSeq;
  if (fromSeq > 1n) {
    const predecessor = await db.auditLog.findUnique({ where: { seq: fromSeq - 1n } });
    if (!predecessor) {
      report({ kind: "SEQUENCE_GAP", seq: (fromSeq - 1n).toString(), detail: "Predecessor of the verified range is missing" });
      expectedPrev = null;
    } else {
      expectedPrev = predecessor.hash;
      prevTimestamp = predecessor.timestamp;
    }
  }

  let checkedRows = 0;
  let last: { seq: bigint; hash: string } | null = null;
  let anchorSeen = false;
  let cursor = fromSeq;

  for (;;) {
    const rows = await db.auditLog.findMany({ where: { seq: { gte: cursor } }, orderBy: { seq: "asc" }, take: batchSize });
    if (rows.length === 0) break;

    for (const row of rows) {
      checkedRows += 1;
      const seqStr = row.seq.toString();
      const firstLegacyPredecessor = row.hashVersion === 1 && row.seq === 1n;

      if (row.seq !== expectedSeq) {
        report({ kind: "SEQUENCE_GAP", seq: seqStr, id: row.id, detail: `Expected seq ${expectedSeq}, found ${seqStr}` });
      }

      // Legacy rows used null (not the genesis hash) for the very first entry.
      const prevMatches =
        expectedPrev === null ||
        row.prevHash === expectedPrev ||
        (firstLegacyPredecessor && expectedPrev === GENESIS_HASH && row.prevHash === null);
      if (!prevMatches) {
        report({ kind: "PREDECESSOR_MISMATCH", seq: seqStr, id: row.id, detail: "prevHash does not match the preceding row's hash" });
      }

      let computed: string | null;
      if (row.hashVersion === 2) {
        computed = computeAuditHashV2({
          seq: row.seq,
          id: row.id,
          timestamp: row.timestamp,
          entityType: row.entityType,
          entityId: row.entityId,
          event: row.event,
          actorId: row.actorIdAtWrite,
          correlationId: row.correlationId,
          metadata: row.metadata,
          prevHash: row.prevHash ?? "",
        });
      } else if (row.hashVersion === 1) {
        computed = computeAuditHashV1(row.prevHash, {
          entityType: row.entityType,
          entityId: row.entityId,
          event: row.event,
          actorId: row.actorIdAtWrite ?? undefined,
          metadata: row.metadata ?? undefined,
        });
      } else {
        computed = null;
        report({ kind: "UNKNOWN_HASH_VERSION", seq: seqStr, id: row.id, detail: `hashVersion ${row.hashVersion}` });
      }
      if (computed !== null && computed !== row.hash) {
        report({ kind: "HASH_MISMATCH", seq: seqStr, id: row.id, detail: "Stored hash does not match the row's contents" });
      }

      if (row.hashVersion >= 2 && prevTimestamp && row.timestamp < prevTimestamp) {
        report({ kind: "TIMESTAMP_REGRESSION", seq: seqStr, id: row.id, detail: "Timestamp is earlier than its predecessor's" });
      }

      if (opts.anchor && row.seq === opts.anchor.seq) {
        anchorSeen = true;
        if (row.hash !== opts.anchor.hash) {
          report({ kind: "ANCHOR_MISMATCH", seq: seqStr, id: row.id, detail: "Row hash differs from the trusted anchor" });
        }
      }

      expectedPrev = row.hash;
      prevTimestamp = row.timestamp;
      expectedSeq = row.seq + 1n;
      last = { seq: row.seq, hash: row.hash };
    }
    cursor = rows[rows.length - 1].seq + 1n;
  }

  if (head) {
    const tipMatches = last ? last.seq === head.seq && last.hash === head.hash : head.seq === 0n || fromSeq > head.seq;
    if (!tipMatches) {
      report({
        kind: "HEAD_MISMATCH",
        seq: (last?.seq ?? 0n).toString(),
        detail: `Chain tip (${last ? last.seq : "none"}) does not match the recorded head (${head.seq})`,
      });
    }
  }
  if (opts.anchor && !anchorSeen && opts.anchor.seq >= fromSeq) {
    report({ kind: "ANCHOR_MISMATCH", seq: opts.anchor.seq.toString(), detail: "Anchored row is no longer present in the chain" });
  }

  return {
    valid: issues.length === 0,
    checkedRows,
    fromSeq: fromSeq.toString(),
    lastSeq: last ? last.seq.toString() : null,
    head: head ? { seq: head.seq.toString(), hash: head.hash } : null,
    issues,
    brokenAt: issues.find((i) => i.id)?.id,
  };
}

export async function getAuditChainHead(db: Db = prisma): Promise<{ seq: string; hash: string } | null> {
  const [head] = await db.$queryRaw<{ seq: bigint; hash: string }[]>`SELECT "seq", "hash" FROM "AuditChainHead" WHERE "id" = 1`;
  return head ? { seq: head.seq.toString(), hash: head.hash } : null;
}
