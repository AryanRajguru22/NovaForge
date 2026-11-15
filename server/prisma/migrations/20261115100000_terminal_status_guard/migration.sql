-- Defence in depth for approval outcomes.
--
-- The application only ever moves a request/action out of PENDING with a
-- compare-and-swap (UPDATE ... WHERE status = 'PENDING'), and nothing moves it
-- again afterwards. This makes the database enforce that rule too, so a
-- decided request cannot be flipped (APPROVED -> REJECTED, EXPIRED -> PENDING,
-- ...) by a bug, a stray script or a compromised application credential.
--
-- It is a guard for ordinary writers, not a defence against a database owner,
-- who can still disable triggers (see Docs/SECURITY.md, "Trust assumptions").
-- Additive only: no existing row is touched and no data is rewritten.

CREATE OR REPLACE FUNCTION "nf_terminal_status_guard"() RETURNS trigger AS $$
BEGIN
  IF OLD."status" <> 'PENDING' AND NEW."status" IS DISTINCT FROM OLD."status" THEN
    RAISE EXCEPTION '% % is already % and its status cannot be changed', TG_TABLE_NAME, OLD."id", OLD."status"
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER "ApprovalRequest_terminal_status_guard"
  BEFORE UPDATE OF "status" ON "ApprovalRequest"
  FOR EACH ROW EXECUTE FUNCTION "nf_terminal_status_guard"();

CREATE TRIGGER "SensitiveAction_terminal_status_guard"
  BEFORE UPDATE OF "status" ON "SensitiveAction"
  FOR EACH ROW EXECUTE FUNCTION "nf_terminal_status_guard"();
