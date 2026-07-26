-- AuditLog.actorId is ON DELETE SET NULL, so deleting a user retroactively
-- nulls actorId on every historical row they acted on -- which breaks the
-- tamper-evident hash chain, since the hash was computed over the actorId
-- value that existed at write time. actorIdAtWrite is a frozen copy with no
-- foreign key: nothing ever mutates it after insert, so it's what the hash
-- is verified against going forward.
ALTER TABLE "AuditLog" ADD COLUMN "actorIdAtWrite" TEXT;

-- Backfill: for every row not yet affected by a user deletion, actorId
-- still holds the true value, so copy it across.
UPDATE "AuditLog" SET "actorIdAtWrite" = "actorId" WHERE "actorIdAtWrite" IS NULL;
