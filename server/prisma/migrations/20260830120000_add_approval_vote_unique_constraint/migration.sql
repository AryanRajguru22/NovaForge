-- Enforces at the database level that an approver can cast at most one vote
-- per approval request. This was previously only checked in application code
-- (a findFirst-then-create in server/src/routes/approvals.ts), which is
-- race-prone: two concurrent requests can both pass the check before either
-- commits. The database is now the authoritative guard against duplicate
-- votes; the application-level check remains only as a fast-path/UX check.
CREATE UNIQUE INDEX "ApprovalVote_requestId_approverId_key" ON "ApprovalVote"("requestId", "approverId");
