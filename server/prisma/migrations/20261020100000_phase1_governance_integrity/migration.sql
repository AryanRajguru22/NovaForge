-- Phase 1: governance integrity.
--
--   1. Per-request immutable policy snapshots (ApprovalRequestPolicyLevel) and
--      an escalation level on ApprovalRequest.
--   2. Vote-time role/weight on ApprovalVote.
--   3. Append-only policy revision history (ApprovalPolicyRevision).
--   4. Fallback-policy cycle/depth guard enforced by the database.
--
-- Everything is additive. No existing column is altered or dropped and no
-- existing row is deleted. Hand-written sections (backfills and triggers) are
-- invisible to `prisma migrate diff`, like the P0 hardening migration.
--
-- Requires PostgreSQL >= 13 (gen_random_uuid()).

-- CreateEnum
CREATE TYPE "SnapshotSource" AS ENUM ('CAPTURED', 'BACKFILLED');

-- AlterTable
ALTER TABLE "ApprovalRequest" ADD COLUMN "escalationLevel" INTEGER NOT NULL DEFAULT 0;

-- CreateTable
CREATE TABLE "ApprovalRequestPolicyLevel" (
    "id" TEXT NOT NULL,
    "requestId" TEXT NOT NULL,
    "level" INTEGER NOT NULL,
    "policyId" TEXT NOT NULL,
    "actionType" TEXT NOT NULL,
    "quorumType" "QuorumType" NOT NULL,
    "minApprovals" INTEGER NOT NULL,
    "eligibleRoles" "Role"[],
    "escalationTimeoutSec" INTEGER NOT NULL,
    "policyRevisionId" TEXT,
    "conflictedUserIds" TEXT[],
    "source" "SnapshotSource" NOT NULL DEFAULT 'CAPTURED',
    "capturedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ApprovalRequestPolicyLevel_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ApprovalPolicyRevision" (
    "id" TEXT NOT NULL,
    "policyId" TEXT NOT NULL,
    "version" INTEGER NOT NULL,
    "changeType" TEXT NOT NULL,
    "changedById" TEXT,
    "snapshot" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ApprovalPolicyRevision_pkey" PRIMARY KEY ("id")
);

-- AlterTable: nullable first; made NOT NULL after the backfill below.
ALTER TABLE "ApprovalVote" ADD COLUMN "roleAtVote" "Role",
ADD COLUMN "weightAtVote" INTEGER,
ADD COLUMN "attributesSource" "SnapshotSource" NOT NULL DEFAULT 'CAPTURED';

-- CreateIndex
CREATE UNIQUE INDEX "ApprovalRequestPolicyLevel_requestId_level_key" ON "ApprovalRequestPolicyLevel"("requestId", "level");

-- CreateIndex
CREATE INDEX "ApprovalRequestPolicyLevel_policyId_idx" ON "ApprovalRequestPolicyLevel"("policyId");

-- CreateIndex
CREATE UNIQUE INDEX "ApprovalPolicyRevision_policyId_version_key" ON "ApprovalPolicyRevision"("policyId", "version");

-- CreateIndex
CREATE INDEX "ApprovalPolicyRevision_policyId_createdAt_idx" ON "ApprovalPolicyRevision"("policyId", "createdAt");

-- AddForeignKey
ALTER TABLE "ApprovalRequestPolicyLevel" ADD CONSTRAINT "ApprovalRequestPolicyLevel_requestId_fkey" FOREIGN KEY ("requestId") REFERENCES "ApprovalRequest"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ApprovalRequestPolicyLevel" ADD CONSTRAINT "ApprovalRequestPolicyLevel_policyId_fkey" FOREIGN KEY ("policyId") REFERENCES "ApprovalPolicy"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- ---------------------------------------------------------------------------
-- Backfill (explicitly labelled; nothing here claims to be historical fact)
--
-- 1. Policy revisions: every existing policy gets a version-1 BACKFILLED
--    revision with an unknown (NULL) author. It never creates a separation-
--    of-duties conflict, because who edited these policies is not recorded.
-- ---------------------------------------------------------------------------
INSERT INTO "ApprovalPolicyRevision" ("id", "policyId", "version", "changeType", "changedById", "snapshot")
SELECT gen_random_uuid()::text, p."id", 1, 'BACKFILLED', NULL, to_jsonb(p)
FROM "ApprovalPolicy" p;

-- 2. Policy levels for every existing request (pending AND terminal).
--    Level 0 is the policy the request points at NOW (which, after a past
--    escalation, is already a fallback policy); deeper levels follow that
--    policy's fallback pointers as they exist NOW, with cycle and depth
--    guards (max 5 escalations). Values are the policy's CURRENT contents,
--    which for a request that predates this migration may differ from what
--    governed it historically -- hence source = 'BACKFILLED'. For terminal
--    requests this is informational only (their outcome is already recorded).
--    For pending requests it is the best available fact and keeps them
--    decidable under the same rules they would have been decided under
--    immediately before this migration.
WITH RECURSIVE chain AS (
  SELECT r."id" AS request_id, p."id" AS policy_id, 0 AS lvl, ARRAY[p."id"] AS path,
         p."fallbackPolicyId" AS next_id, p."actionType", p."quorumType",
         p."minApprovals", p."eligibleRoles", p."escalationTimeoutSec"
  FROM "ApprovalRequest" r
  JOIN "ApprovalPolicy" p ON p."id" = r."policyId"
  UNION ALL
  SELECT c.request_id, p."id", c.lvl + 1, c.path || p."id",
         p."fallbackPolicyId", p."actionType", p."quorumType",
         p."minApprovals", p."eligibleRoles", p."escalationTimeoutSec"
  FROM chain c
  JOIN "ApprovalPolicy" p ON p."id" = c.next_id
  WHERE NOT (p."id" = ANY (c.path)) AND c.lvl < 5
)
INSERT INTO "ApprovalRequestPolicyLevel"
  ("id", "requestId", "level", "policyId", "actionType", "quorumType", "minApprovals",
   "eligibleRoles", "escalationTimeoutSec", "policyRevisionId", "conflictedUserIds", "source")
SELECT gen_random_uuid()::text, request_id, lvl, policy_id, "actionType", "quorumType", "minApprovals",
       "eligibleRoles", "escalationTimeoutSec", NULL, ARRAY[]::TEXT[], 'BACKFILLED'
FROM chain;

-- 3. Vote-time role and weight. The role/weight a voter had when they voted
--    was never recorded, so the only available values are the voter's
--    CURRENT ones. They are flagged BACKFILLED; for votes on already-pending
--    requests this is exactly what the tally used before this migration
--    (no behaviour change at migration time). ApprovalVote rows are
--    immutable, so the guard is lifted for this one statement only, inside
--    this migration's transaction.
ALTER TABLE "ApprovalVote" DISABLE TRIGGER "ApprovalVote_before_update_immutable";

UPDATE "ApprovalVote" v
SET "roleAtVote" = u."role",
    "weightAtVote" = u."voteWeight",
    "attributesSource" = 'BACKFILLED'
FROM "User" u
WHERE u."id" = v."approverId";

ALTER TABLE "ApprovalVote" ENABLE TRIGGER "ApprovalVote_before_update_immutable";

ALTER TABLE "ApprovalVote" ALTER COLUMN "roleAtVote" SET NOT NULL,
ALTER COLUMN "weightAtVote" SET NOT NULL;

-- ---------------------------------------------------------------------------
-- Database-enforced invariants
-- ---------------------------------------------------------------------------

-- A snapshot level is written once. (Deleting a request cascades to its
-- levels; nothing in the application deletes requests.)
CREATE FUNCTION "novaforge_policy_level_before_update"() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'approval request policy snapshots are immutable';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER "ApprovalRequestPolicyLevel_immutable"
BEFORE UPDATE ON "ApprovalRequestPolicyLevel"
FOR EACH ROW EXECUTE FUNCTION "novaforge_policy_level_before_update"();

-- Policy history is append-only (novaforge_reject_modification is defined in
-- the P0 hardening migration).
CREATE TRIGGER "ApprovalPolicyRevision_before_update_append_only"
BEFORE UPDATE ON "ApprovalPolicyRevision"
FOR EACH ROW EXECUTE FUNCTION "novaforge_reject_modification"();

CREATE TRIGGER "ApprovalPolicyRevision_before_delete_append_only"
BEFORE DELETE ON "ApprovalPolicyRevision"
FOR EACH ROW EXECUTE FUNCTION "novaforge_reject_modification"();

-- Fallback chains must be acyclic and short, for EVERY writer. The advisory
-- lock serialises policy-graph writers, so two concurrent updates (A -> B and
-- B -> A) cannot each pass the check against a graph the other has yet to
-- commit: the second one blocks here until the first commits, and then sees
-- its row. The application takes the same lock (key 727001) before its own
-- pre-check to return friendly errors; this trigger is the backstop.
-- Max chain: the policy itself plus 5 fallbacks (MAX_ESCALATIONS in
-- server/src/lib/policySnapshot.ts).
CREATE FUNCTION "novaforge_policy_fallback_guard"() RETURNS trigger AS $$
DECLARE
  cur   TEXT;
  steps INTEGER := 0;
BEGIN
  IF NEW."fallbackPolicyId" IS NULL THEN
    RETURN NEW;
  END IF;
  PERFORM pg_advisory_xact_lock(727001);
  cur := NEW."fallbackPolicyId";
  WHILE cur IS NOT NULL LOOP
    IF cur = NEW."id" THEN
      RAISE EXCEPTION 'approval policy fallback cycle detected' USING ERRCODE = '23514';
    END IF;
    steps := steps + 1;
    IF steps > 5 THEN
      RAISE EXCEPTION 'approval policy fallback chain is longer than 5' USING ERRCODE = '23514';
    END IF;
    SELECT "fallbackPolicyId" INTO cur FROM "ApprovalPolicy" WHERE "id" = cur;
  END LOOP;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER "ApprovalPolicy_fallback_guard"
BEFORE INSERT OR UPDATE OF "fallbackPolicyId" ON "ApprovalPolicy"
FOR EACH ROW EXECUTE FUNCTION "novaforge_policy_fallback_guard"();
