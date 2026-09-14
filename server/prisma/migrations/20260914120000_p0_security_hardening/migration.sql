-- P0 security hardening: account status, enrollment tokens, fallback-factor
-- throttling, TOTP replay protection, decision-bound approval evidence,
-- linear append-only audit chain, and service identities.
--
-- The Prisma-generated parts are unchanged apart from the AuditLog.seq
-- backfill. Everything under "Database-enforced invariants" is hand-written
-- (Prisma's schema language can't express triggers) and is invisible to
-- `prisma migrate diff`, so future generated migrations will not touch it.

-- CreateEnum
CREATE TYPE "AccountStatus" AS ENUM ('ACTIVE', 'SUSPENDED', 'DISABLED');

-- AlterEnum
ALTER TYPE "ActionStatus" ADD VALUE 'POSTPONED';

-- AlterEnum
ALTER TYPE "VoteDecision" ADD VALUE 'POSTPONE';

-- AlterTable
ALTER TABLE "ApprovalVote" ADD COLUMN     "authenticatorData" TEXT,
ADD COLUMN     "clientDataJSON" TEXT,
ADD COLUMN     "credentialPublicKey" TEXT,
ADD COLUMN     "reason" TEXT,
ADD COLUMN     "signedStatement" TEXT,
ADD COLUMN     "statementHash" TEXT;

-- AlterTable
ALTER TABLE "Credential" ADD COLUMN     "totpLastUsedStep" BIGINT;

-- AlterTable
ALTER TABLE "SensitiveAction" ADD COLUMN     "payloadDigest" TEXT;

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "status" "AccountStatus" NOT NULL DEFAULT 'ACTIVE',
ADD COLUMN     "statusChangedAt" TIMESTAMP(3);

-- CreateTable
CREATE TABLE "EnrollmentToken" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "usedAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),

    CONSTRAINT "EnrollmentToken_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuthThrottle" (
    "subject" TEXT NOT NULL,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "lockLevel" INTEGER NOT NULL DEFAULT 0,
    "lockedUntil" TIMESTAMP(3),
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AuthThrottle_pkey" PRIMARY KEY ("subject")
);

-- CreateTable
CREATE TABLE "AuditChainHead" (
    "id" INTEGER NOT NULL,
    "seq" BIGINT NOT NULL,
    "hash" TEXT NOT NULL,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuditChainHead_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ServiceAccount" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "audience" TEXT NOT NULL,
    "status" "AccountStatus" NOT NULL DEFAULT 'ACTIVE',
    "scopes" TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdById" TEXT,

    CONSTRAINT "ServiceAccount_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ServiceCredential" (
    "id" TEXT NOT NULL,
    "serviceAccountId" TEXT NOT NULL,
    "secretHash" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "lastUsedAt" TIMESTAMP(3),

    CONSTRAINT "ServiceCredential_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "EnrollmentToken_tokenHash_key" ON "EnrollmentToken"("tokenHash");

-- CreateIndex
CREATE INDEX "EnrollmentToken_userId_idx" ON "EnrollmentToken"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "ServiceAccount_name_key" ON "ServiceAccount"("name");

-- CreateIndex
CREATE UNIQUE INDEX "ServiceAccount_audience_key" ON "ServiceAccount"("audience");

-- CreateIndex
CREATE INDEX "ServiceCredential_serviceAccountId_idx" ON "ServiceCredential"("serviceAccountId");

-- AddForeignKey
ALTER TABLE "EnrollmentToken" ADD CONSTRAINT "EnrollmentToken_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EnrollmentToken" ADD CONSTRAINT "EnrollmentToken_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ServiceCredential" ADD CONSTRAINT "ServiceCredential_serviceAccountId_fkey" FOREIGN KEY ("serviceAccountId") REFERENCES "ServiceAccount"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- ---------------------------------------------------------------------------
-- AuditLog: explicit chain position.
--
-- Existing (legacy, hashVersion 1) rows get a seq that follows the chain's
-- OWN links: starting from the genesis row (prevHash NULL) and repeatedly
-- taking the row whose prevHash is the current row's hash. Ordering by
-- timestamp instead would misorder rows the old append wrote within the same
-- millisecond, and verification would then report a legitimate chain as
-- broken. Where a link is ambiguous (a fork: several rows claim the same
-- predecessor) a branch that continues is preferred over a dead end, then the
-- earliest (timestamp, id); every row not
-- reachable this way (fork branches, orphans) is placed after the chain in
-- (timestamp, id) order. Hashes are NOT recomputed: forks and orphans remain
-- visible to verification and are never silently repaired.
-- ---------------------------------------------------------------------------
ALTER TABLE "AuditLog" ADD COLUMN     "correlationId" TEXT,
ADD COLUMN     "hashVersion" INTEGER NOT NULL DEFAULT 1,
ADD COLUMN     "seq" BIGINT;

-- Temporary: keeps the link walk below linear rather than quadratic.
CREATE INDEX "AuditLog_backfill_prevHash_idx" ON "AuditLog"("prevHash");

WITH RECURSIVE chain AS (
  SELECT g."id", g."hash", 1::BIGINT AS depth
  FROM (
    SELECT "id", "hash" FROM "AuditLog" WHERE "prevHash" IS NULL ORDER BY "timestamp" ASC, "id" ASC LIMIT 1
  ) AS g
  UNION ALL
  SELECT n."id", n."hash", c.depth + 1
  FROM chain AS c
  CROSS JOIN LATERAL (
    SELECT x."id", x."hash" FROM "AuditLog" AS x
    WHERE x."prevHash" = c."hash"
    -- At a fork, prefer a branch that continues over a dead end.
    ORDER BY EXISTS (SELECT 1 FROM "AuditLog" AS y WHERE y."prevHash" = x."hash") DESC, x."timestamp" ASC, x."id" ASC
    LIMIT 1
  ) AS n
  WHERE c.depth < (SELECT COUNT(*) FROM "AuditLog")
)
UPDATE "AuditLog" AS a
SET "seq" = chain.depth
FROM chain
WHERE a."id" = chain."id";

UPDATE "AuditLog" AS a
SET "seq" = o.rn + COALESCE((SELECT MAX("seq") FROM "AuditLog"), 0)
FROM (
  SELECT "id", ROW_NUMBER() OVER (ORDER BY "timestamp" ASC, "id" ASC) AS rn FROM "AuditLog" WHERE "seq" IS NULL
) AS o
WHERE a."id" = o."id";

DROP INDEX "AuditLog_backfill_prevHash_idx";

ALTER TABLE "AuditLog" ALTER COLUMN "seq" SET NOT NULL;

-- CreateIndex
CREATE UNIQUE INDEX "AuditLog_seq_key" ON "AuditLog"("seq");

-- The chain tip. Genesis (empty chain) is seq 0 with 64 zero hex digits.
INSERT INTO "AuditChainHead" ("id", "seq", "hash", "updatedAt")
SELECT 1,
       COALESCE((SELECT "seq" FROM "AuditLog" ORDER BY "seq" DESC LIMIT 1), 0),
       COALESCE((SELECT "hash" FROM "AuditLog" ORDER BY "seq" DESC LIMIT 1), repeat('0', 64)),
       CURRENT_TIMESTAMP;

ALTER TABLE "AuditChainHead" ADD CONSTRAINT "AuditChainHead_singleton" CHECK ("id" = 1);

-- ---------------------------------------------------------------------------
-- Database-enforced invariants
--
-- These hold for every writer, not just NovaForge's own code paths. They
-- are tamper *resistance* against the application role; a database owner
-- can still disable triggers (e.g. session_replication_role = replica),
-- which is exactly what hash-chain verification exists to detect.
-- ---------------------------------------------------------------------------

-- Linear chain: a new row must be exactly head.seq + 1 and point at
-- head.hash. The head row is locked FOR UPDATE, so concurrent inserts queue
-- behind each other and a second writer that computed against a stale head
-- is rejected instead of creating a fork.
CREATE FUNCTION "novaforge_audit_before_insert"() RETURNS trigger AS $$
DECLARE
  head_seq  BIGINT;
  head_hash TEXT;
BEGIN
  SELECT "seq", "hash" INTO head_seq, head_hash FROM "AuditChainHead" WHERE "id" = 1 FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'audit chain integrity: chain head is missing';
  END IF;
  IF NEW."hashVersion" < 2 THEN
    RAISE EXCEPTION 'audit chain integrity: new rows must use hashVersion >= 2';
  END IF;
  IF NEW."seq" <> head_seq + 1 THEN
    RAISE EXCEPTION 'audit chain integrity: seq % does not directly follow head seq %', NEW."seq", head_seq;
  END IF;
  IF NEW."prevHash" IS DISTINCT FROM head_hash THEN
    RAISE EXCEPTION 'audit chain integrity: prevHash of seq % does not match the chain head', NEW."seq";
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER "AuditLog_before_insert_chain"
BEFORE INSERT ON "AuditLog"
FOR EACH ROW EXECUTE FUNCTION "novaforge_audit_before_insert"();

CREATE FUNCTION "novaforge_audit_after_insert"() RETURNS trigger AS $$
BEGIN
  UPDATE "AuditChainHead" SET "seq" = NEW."seq", "hash" = NEW."hash", "updatedAt" = CURRENT_TIMESTAMP WHERE "id" = 1;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER "AuditLog_after_insert_head"
AFTER INSERT ON "AuditLog"
FOR EACH ROW EXECUTE FUNCTION "novaforge_audit_after_insert"();

-- Append-only rows. The single permitted UPDATE is the ON DELETE SET NULL
-- of the actorId foreign key when a user is deleted -- actorId is not part
-- of the hash (actorIdAtWrite is), so that never affects verification.
CREATE FUNCTION "novaforge_audit_before_update"() RETURNS trigger AS $$
BEGIN
  IF NEW."actorId" IS NULL
     AND NEW."id" = OLD."id"
     AND NEW."entityType" = OLD."entityType"
     AND NEW."entityId" = OLD."entityId"
     AND NEW."event" = OLD."event"
     AND NEW."actorIdAtWrite" IS NOT DISTINCT FROM OLD."actorIdAtWrite"
     AND NEW."metadata" IS NOT DISTINCT FROM OLD."metadata"
     AND NEW."timestamp" = OLD."timestamp"
     AND NEW."prevHash" IS NOT DISTINCT FROM OLD."prevHash"
     AND NEW."hash" = OLD."hash"
     AND NEW."seq" = OLD."seq"
     AND NEW."hashVersion" = OLD."hashVersion"
     AND NEW."correlationId" IS NOT DISTINCT FROM OLD."correlationId" THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'audit log rows are append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER "AuditLog_before_update_append_only"
BEFORE UPDATE ON "AuditLog"
FOR EACH ROW EXECUTE FUNCTION "novaforge_audit_before_update"();

CREATE FUNCTION "novaforge_reject_modification"() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '% on "%" is not permitted', TG_OP, TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER "AuditLog_before_delete_append_only"
BEFORE DELETE ON "AuditLog"
FOR EACH ROW EXECUTE FUNCTION "novaforge_reject_modification"();

CREATE TRIGGER "AuditLog_before_truncate_append_only"
BEFORE TRUNCATE ON "AuditLog"
FOR EACH STATEMENT EXECUTE FUNCTION "novaforge_reject_modification"();

-- The head may only move via the AuditLog insert trigger above (trigger
-- depth >= 2); a direct UPDATE/DELETE/TRUNCATE is rejected.
CREATE FUNCTION "novaforge_audit_head_guard"() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND pg_trigger_depth() >= 2 THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'the audit chain head can only advance by appending an audit row';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER "AuditChainHead_guard"
BEFORE UPDATE OR DELETE ON "AuditChainHead"
FOR EACH ROW EXECUTE FUNCTION "novaforge_audit_head_guard"();

CREATE TRIGGER "AuditChainHead_before_truncate"
BEFORE TRUNCATE ON "AuditChainHead"
FOR EACH STATEMENT EXECUTE FUNCTION "novaforge_reject_modification"();

-- A recorded vote (decision + signature evidence) can never be rewritten.
CREATE TRIGGER "ApprovalVote_before_update_immutable"
BEFORE UPDATE ON "ApprovalVote"
FOR EACH ROW EXECUTE FUNCTION "novaforge_reject_modification"();

-- What was requested (and what approvers signed a digest of) can never be
-- rewritten after creation. Only status transitions are permitted.
CREATE FUNCTION "novaforge_sensitive_action_before_update"() RETURNS trigger AS $$
BEGIN
  IF NEW."id" <> OLD."id"
     OR NEW."type" <> OLD."type"
     OR NEW."payload" IS DISTINCT FROM OLD."payload"
     OR NEW."payloadDigest" IS DISTINCT FROM OLD."payloadDigest"
     OR NEW."requestedById" <> OLD."requestedById"
     OR NEW."createdAt" <> OLD."createdAt" THEN
    RAISE EXCEPTION 'SensitiveAction subject fields are immutable; only status may change';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER "SensitiveAction_before_update_immutable_subject"
BEFORE UPDATE ON "SensitiveAction"
FOR EACH ROW EXECUTE FUNCTION "novaforge_sensitive_action_before_update"();
