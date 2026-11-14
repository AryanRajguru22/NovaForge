# NovaForge Phase 1 — Governance Integrity Report

| | |
|---|---|
| **Date** | 2026-10-20 |
| **Base commit** | `5f3a2a6` on `main` (nothing committed, nothing pushed) |
| **Scope** | Phase 1 of `Docs/PROJECT_STATUS_AND_ROADMAP.md` (findings F-01, F-06, F-07, F-12) |
| **Verification database** | Disposable PostgreSQL 16 container on `127.0.0.1:55432`. The user's own database was never targeted. |

---

## 1. Executive summary

Approval rules are now fixed per request, vote outcomes no longer depend on a voter's *current* role or weight, privileged governance operations require a fresh passkey proof on the server, and fallback policies can no longer form cycles.

- **Policy snapshots.** Creating an approval request copies the matched policy *and its whole fallback chain* into immutable `ApprovalRequestPolicyLevel` rows in the same transaction. Voting, tallying, eligibility, socket authorisation and escalation read only those rows. Editing or deleting the live policy affects only later requests.
- **Frozen voter attributes.** Every vote records `roleAtVote` / `weightAtVote`, read under a row lock in the vote transaction. The tally uses them.
- **Governed mutations.** Policy create/update/delete and user role/weight/status/delete now require, on the server: the existing role guard, sufficient effective session trust, and a single-use, purpose-bound passkey assertion with user verification. Refusals are audited. The frontend performs the ceremony; the server does not rely on it.
- **Separation of duties.** The author of the policy revision a request captured (or of any revision of its policies in the preceding 24 h) cannot see it as pending or vote on it. The set is fixed at creation under a row lock, so it is race-free.
- **Cycle prevention.** Cycle and depth checks run under a database advisory lock in the application and again in a database trigger, so concurrent updates cannot jointly create a cycle. Escalation walks a finite pre-captured chain whose level only increases, so it always terminates.
- **Result.** Full server suite: **267 / 267 passing** (240 pre-existing + 27 new) on a database built from the migrations from scratch, and again on a re-used database earlier in the work; the final run (after the last code change) was on a fresh database. Typecheck, Prisma validate, schema-vs-migration drift check and client build all pass. Negative controls confirm the key new tests fail when the protection they cover is removed.

Not done / not claimed: see §10. Nothing was committed or pushed. The migration has **not** been applied to your existing development database.

---

## 2. Findings confirmed before implementation

Verified against the code at `5f3a2a6`, not taken from the audit report:

| Finding | Evidence at the start of Phase 1 |
|---|---|
| Vote evaluation used the **live** policy | `approvals.ts` vote transaction: `tx.approvalPolicy.findUnique({ where: { id: lockedRequest.policyId } })`. Eligibility, `minApprovals`, `quorumType`, `eligibleRoles` all came from it. |
| Escalation used live policies | `escalation.ts` read `policy.fallbackPolicyId` and the fallback policy's current row at escalation time. |
| Socket join and `/pending` / `/history` used the live policy | `socketSecurity.ts` `include: { policy: true }`; `/pending` filtered `policy: { eligibleRoles: { has } }`. |
| Tally used **current** voter attributes | `include: { approver: true }`; `approver.role` and `approver.voteWeight` read at evaluation time (contradicting the schema comment). |
| No step-up on governance routes | `policies.ts` POST/PUT/DELETE: `requireAuth, requireAdmin` only. `users.ts` role/weight/status/delete: `requireSuperAdmin` only. Step-up existed only for enrollment tokens, TOTP enrolment and recovery codes. |
| Only self-reference rejected | `policies.ts`: `data.fallbackPolicyId === id` was the only fallback check; A→B→A was accepted. |
| Last-super-admin guard was check-then-act | `users.ts` counted super admins outside the transaction. |
| Policy deletion semantics | Request FK was `RESTRICT`; no check that a policy was another policy's fallback. |

---

## 3. Exact changes

### Migration (additive)
`server/prisma/migrations/20261020100000_phase1_governance_integrity/migration.sql`
- Enum `SnapshotSource` (`CAPTURED`, `BACKFILLED`).
- `ApprovalRequest.escalationLevel INTEGER NOT NULL DEFAULT 0`.
- New table `ApprovalRequestPolicyLevel` (immutable; FK to request `ON DELETE CASCADE`, FK to policy `ON DELETE RESTRICT`).
- New table `ApprovalPolicyRevision` (append-only, no foreign keys).
- `ApprovalVote.roleAtVote`, `weightAtVote` (made `NOT NULL` after backfill), `attributesSource`.
- Triggers: `ApprovalRequestPolicyLevel_immutable`, `ApprovalPolicyRevision_before_update/delete_append_only`, `ApprovalPolicy_fallback_guard`.
- `schema.prisma` updated to match; `prisma migrate diff` reports no drift.

### Server
| File | Change |
|---|---|
| `server/src/lib/policySnapshot.ts` (new) | `captureGoverningPolicy` (chain walk under `FOR SHARE`), `effectiveLevel`, `nextLevel`, `isPolicyEditorConflict`, `presentGoverningPolicy`; constants `MAX_ESCALATIONS = 5`, `POLICY_EDIT_COOLING_OFF_MS = 24h`, `POLICY_GRAPH_LOCK_KEY = 727001`. |
| `server/src/lib/governance.ts` (new) | `governanceTrust`, `governanceStepUpOptions`, `enforceGovernanceStepUp` (audits refusals), `lockPolicyGraph`, `lockSuperAdminSet` (key 727002). |
| `server/src/lib/stepUp.ts` | New purposes `policy-governance`, `user-governance`. |
| `server/src/middleware/requireTrust.ts` | Optional `onDeny` hook (default behaviour unchanged). |
| `server/src/routes/actions.ts` | Request creation captures the snapshot atomically; GETs present the frozen policy. |
| `server/src/routes/approvals.ts` | Options/vote/pending/history read snapshots; vote transaction reads the escalation level under the row lock, reads the voter with `FOR SHARE`, records `roleAtVote`/`weightAtVote`, tallies from them, enforces separation of duties. |
| `server/src/lib/escalation.ts` | Escalation = compare-and-swap to the next frozen level (`escalationLevel`, `expiresAt` in the `WHERE`); last level → `EXPIRED`. |
| `server/src/lib/socketSecurity.ts` | Join authorisation uses the frozen level. |
| `server/src/routes/policies.ts` | Step-up + trust on create/update/delete; one transaction behind the policy-graph lock; cycle/depth check; revisions written; delete also refused when the policy is another's fallback. New `POST /policies/step-up/options`. |
| `server/src/routes/users.ts` | Step-up + trust on role/weight/status/delete; last-super-admin recount inside the transaction behind an advisory lock. New `POST /users/governance/step-up/options`. Invitations (which can create a `SUPER_ADMIN`) and enrollment-token issuance now also get the trust check and audited step-up refusals (they already required step-up). |

### Client
`client/src/lib/stepUp.ts` (new), `client/src/lib/api.ts` (`apiDelete` accepts a body), `client/src/pages/PolicyManagement.tsx`, `client/src/pages/UserManagement.tsx` (request a challenge, sign it, send `response` with the mutation).

### Tests
New `server/test/phase1-governance.test.ts` (27 tests). Helpers `governanceProof` and `createApprovalRequestWithSnapshot` in `server/test/testServer.ts`. Existing tests adjusted — see §8.

---

## 4. Policy snapshots and fallback semantics

- **What is captured.** For each level: `policyId`, `actionType`, `quorumType`, `minApprovals`, `eligibleRoles`, `escalationTimeoutSec`, the id of the policy revision in force, and `conflictedUserIds`. Weighted quorum has no per-policy weight table: the rule is the threshold (`minApprovals`) plus each voter's weight, which is frozen on the vote (§5).
- **Fallback chain.** Level 0 is the policy matched for the action type; level *n+1* is the `fallbackPolicyId` of level *n* **as it was at creation**. The entire chain is captured up front (decision: the escalation path of an in-flight request is as immutable as its rules; editing a fallback policy later does not redirect existing requests).
- **Escalation.** When `expiresAt` passes, the request moves to level *n+1* (`escalationLevel`, `policyId`, new `expiresAt = now + that level's own timeout`) via a compare-and-swap that includes the current level, so a duplicate pass or a racing vote cannot double-advance it. Votes already cast carry over and are re-evaluated under the new level's rules (this is the pre-existing behaviour, unchanged). After the last level the request and action become `EXPIRED`.
- **Race-free capture.** Capture reads each policy `FOR SHARE`; policy writers take `FOR UPDATE` on the same row and write the revision in the same transaction. A request therefore captures a policy entirely before or entirely after any concurrent edit (tested: values always equal the captured revision's).
- **Fail closed.** A request with no snapshot level for its escalation level is never decided from the live policy: options/vote return 409; sockets deny; `/pending` omits it.
- **Policy deletion.** Snapshot rows hold `RESTRICT` FKs, so a policy that any snapshot names cannot be deleted; policies used as a fallback cannot be deleted either.
- **Compatibility note.** `GET` responses keep the `approvalRequest.policy` shape clients already read, but it is now the frozen level (`id` = the policy it was copied from), with extra fields `level`, `levelCount`, `source`.

---

## 5. Vote-time role and weight

- Inside the vote transaction, after the request row is locked, the voter row is read `SELECT "role","voteWeight","status" … FOR SHARE`. A concurrent role/weight change either commits before that read or waits for the transaction.
- Eligibility is judged against that fresh role and the frozen level (the voter must *currently* hold an eligible role and be `ACTIVE`); the same values are written to the vote as `roleAtVote` / `weightAtVote` in the same insert.
- `ROLE_BASED` counts distinct `roleAtVote`; `WEIGHTED` sums `weightAtVote`; neither joins `User` any more.
- The existing `ApprovalVote` update-immutability trigger covers the new columns (tested).
- **Tests** demonstrate the old behaviour would have produced a different outcome: weight 3 → 1 after voting (frozen total 3+2=5 → APPROVED; old logic 1+2=3 → PENDING), and APPROVER demoted to MEMBER after voting (ROLE_BASED satisfied from frozen roles; old logic not).

---

## 6. Step-up and separation of duties

**Per-mutation requirements (server-enforced, in this order):** `requireAuth` → role guard (`ADMIN`/`SUPER_ADMIN` for policies, `SUPER_ADMIN` for users; unchanged RBAC) → `governanceTrust` (effective decayed trust ≥ 50; refusal audited as `GOVERNANCE_TRUST_DENIED`) → body validation → `enforceGovernanceStepUp` → transaction.

**Step-up behaviour** (reuses `beginStepUp` / `verifyStepUp`, passkey with user verification required, challenge single-use, 5-minute TTL, keyed by purpose + user):

| Condition | Result |
|---|---|
| No `response` | `403 STEP_UP_REQUIRED`, nothing consumed, audited |
| Garbage / not a valid assertion / signed by another user's key | `400 STEP_UP_FAILED`, audited |
| Replay of a used assertion | `400 STEP_UP_FAILED` |
| Challenge older than TTL | `400` "expired" |
| Proof minted for the *other* purpose | `400` (no outstanding challenge for this purpose) |
| Assertion without user verification | `400 STEP_UP_FAILED` |
| Session trust too low | `403` + audit |

Successful operations are audited in the same transaction as the change (existing `POLICY_*`, `ROLE_CHANGED`, `VOTE_WEIGHT_CHANGED`, `ACCOUNT_STATUS_CHANGED`, `USER_DELETED`), now with `stepUpCredentialId`; the authenticator counter is advanced in that transaction. Policy changes additionally write an `ApprovalPolicyRevision`.

**Covered endpoints:** `POST/PUT/DELETE /policies`, `PATCH /users/:id/role|weight|status`, `DELETE /users/:id`, and — added after review because an invitation can create a `SUPER_ADMIN` — `POST /users/invitations` and `POST /users/:id/enrollment-token`. The last two keep their original step-up ceremony (`POST /users/step-up/options`, purpose `enrollment-token`) but now also pass `governanceTrust` and use `enforceGovernanceStepUp`, so missing/invalid proofs are audited. Their response codes for forged proofs (400) are unchanged; a *missing* proof is now `403 STEP_UP_REQUIRED` instead of a 400 validation error.

**Separation of duties.** A user is conflicted for a request if they authored the policy revision captured at any of its levels, or any revision of those policies in the 24 h before creation. The set is stored on the level at creation. Conflicted users: options and vote → `403`; not listed in `/approvals/pending`. Because the set is fixed under the capture lock, an edit racing a vote cannot change the verdict for an existing request (tested). Edits made *after* a request exists never disqualify anyone from it retroactively.

**Other safeguards.** The last-active-super-admin guard (role/status/delete) is recounted inside the transaction behind an advisory lock; tested with two super admins demoting each other with both requests forced past authorisation before either commits (exactly one succeeds). Role/status checks on the target, self-targeting rules and last-super-admin messages are unchanged.

---

## 7. Cycle detection and escalation termination

- **Application.** Policy create/update run in one transaction behind `pg_advisory_xact_lock(727001)`. `assertValidFallback` follows the proposed fallback; reaching the edited policy (A→B→A, A→C→B→A, …) → `400` "must not form a cycle"; more than `MAX_ESCALATIONS` (5) fallbacks → `400` "at most 5". A concurrent edit blocks on the lock and then sees the other's committed row.
- **Database backstop.** `ApprovalPolicy_fallback_guard` (BEFORE INSERT / UPDATE OF `fallbackPolicyId`) takes the same lock and walks the chain, raising SQLSTATE `23514` for cycle or over-long chain — so any writer, not just the API, is covered. Tested with two concurrent raw `UPDATE`s: exactly one fails.
- **Termination.** The snapshot chain is finite (≤ 6 levels), built with a seen-set and depth cap, and `escalationLevel` only moves forward. Legacy data that already contains a cycle is truncated at the revisit; tested by planting A→B→A (trigger bypass in a test transaction) and escalating: level 1, then `EXPIRED`, never back to A.

---

## 8. Tests — commands and actual results

All against disposable Postgres 16 (`postgres:16-alpine`, port 55432, no volume). `DATABASE_URL` was overridden in the shell and the Prisma "Datasource … at localhost:55432" line was checked before running.

| Command (cwd) | Result |
|---|---|
| `npx tsc -p tsconfig.json --noEmit` (`server/`) | Pass |
| `npx prisma validate` (`server/`) | Pass |
| `npx prisma migrate deploy` on an empty DB | Pass — all 10 migrations applied |
| `npx prisma migrate diff --from-url <db> --to-schema-datamodel prisma/schema.prisma --exit-code` | Pass — "No difference detected" |
| `npx vitest run` — fresh DB (before the final invitation change) | 28 files, 267 passed (174 s) |
| `npx vitest run` — second run on that same, used DB | 28 files, 267 passed (169 s) |
| `npx vitest run` — **final**, fresh DB, after the last code change | **28 files, 267 tests passed, 0 failed, 0 skipped** (190 s) |
| `npm run build` (`client/`; `tsc -b && vite build`) | Pass — final run re-done after the last change |
| Migration on **legacy data** (see §9) | Pass; backfill and triggers verified by query |

New file `phase1-governance.test.ts` (27 tests), mapped to the requested minimum:

| Requested test | Covered by |
|---|---|
| 1 Policy edit doesn't alter in-flight rules | "editing a policy does not alter an already-created request's effective rules"; "captures the whole fallback chain …" |
| 2 Concurrent edit + vote can't bypass | "a vote racing a weakening edit is decided under the original rules every time" (4 iterations); "a request created while the policy is being edited captures one coherent revision" (6 iterations) |
| 3 Role/weight changes don't alter earlier votes | the WEIGHTED and ROLE_BASED tests; DB immutability test |
| 4 Governance mutations fail without fresh step-up | missing / invalid / foreign key / replay / expired / wrong-purpose / no-UV / low-trust, over all 7 mutation endpoints; RBAC unchanged; audit assertions |
| 5 Policy editor can't vote | SoD tests (options, vote, pending list; creation-time fixation; race) |
| 6 Cycles rejected incl. concurrently | 2- and 3-cycles, depth cap, two concurrent API updates (4 trials), two concurrent raw SQL updates |
| 7 Escalation terminates, fail-closed | chain escalation to expiry; legacy-cycle data; no-fallback expiry |
| 8 Existing suites still pass | 240 pre-existing tests in the 267 total |

**Negative controls** (protection removed → matching test must fail; code restored afterwards, `NEGCTL` markers verified absent):
- Tallying from the voter's current weight/role → both frozen-attribute tests fail.
- Removing the policy-graph lock *and* the DB trigger → the concurrent-cycle test fails.
- Super-admin race: (a) removing the lock call makes the test fail, but only because its harness times out waiting for two lock waiters — that shows the lock is taken, not what it protects; (b) the meaningful variant keeps the lock but counts super admins *before* taking it (check-then-act): both demotions return `200` (`expected [200, 200] to equal [200, 400]`), leaving **no** active super admin. That is the outcome the in-transaction recount prevents.
- Not mutation-tested: the step-up and trust refusals (removing them is trivially visible in the missing-proof test) and the separation-of-duties check.

**Existing tests that had to change, and why** (no assertion weakened to hide a regression; each reflects an intended behavioural change):
- `policies.test.ts`, `user-deletion.test.ts`, `audit.test.ts`, `p0-6-identity-trust.test.ts`: governance calls now carry a real passkey proof from a software authenticator.
- `approvals.test.ts`: the direct-insert race test supplies the new NOT NULL `roleAtVote`/`weightAtVote`.
- `expiry-race.test.ts`, `vote-eligibility-race.test.ts`, `p0-4-decision-binding.test.ts`: requests built directly now get a real snapshot (`createApprovalRequestWithSnapshot`, which uses the production capture); the hand-rolled "reassignment" sets `escalationLevel: 1`, which is what escalation now does.
- `socket-security.test.ts` TEST 15: it asserted that editing the **live** policy changes who may join. That is exactly what Phase 1 removes. The test now asserts that a live edit does **not** change access, and that escalation to a level with different roles **does**, on the next join.
- One bug in my own new test (a fake-clock test wrote an audit row with a future timestamp, which the audit chain's monotonic clamp then carried forward and tripped existing audit tests) was fixed by issuing the challenge under a *past* clock instead, so no audit row is written under a faked clock.

---

## 9. Migration, backfill and rollback

**Applying.** `prisma migrate deploy` (runs automatically in the production containers). Requires PostgreSQL ≥ 13 (`gen_random_uuid()`). **Not applied to your existing development database** — that is your decision; the disposable database was used for every check.

**Backfill (labelled `BACKFILLED`, never presented as history):**
- *Policy levels* for **every** existing request (pending and terminal): level 0 = the policy the request points at *now* (after a past escalation that is already the fallback), deeper levels follow that policy's fallback pointers *now*, with cycle and depth guards. Values are the policies' **current** contents, which may differ from what governed the request historically. For terminal requests this is informational; for pending requests it is the best available fact and keeps them decidable under the rules they would have had immediately before the migration. `escalationLevel` = 0. `conflictedUserIds` = **empty** (see the limitation below).
- *Policy revisions*: one `BACKFILLED` version-1 revision per existing policy with the author left NULL — so it never causes a separation-of-duties conflict.
- **Limitation (deliberate, not "unknown data").** Policy edits made through the API before Phase 1 *are* recorded in the audit chain (`POLICY_CREATED` / `POLICY_UPDATED` with `actorIdAtWrite`). The migration does not mine them: it would have to join audit metadata to policies in SQL and decide which edits "govern" which pending request. Consequence: a **legacy pending request has no editor-conflict set**, so its policy's pre-Phase-1 editor can still vote on it. Requests created after the migration are fully covered. If that matters for your data, backfill `changedById` / `conflictedUserIds` from the audit rows before putting real pending requests through the migration.
- *Votes*: `roleAtVote` / `weightAtVote` = the voter's **current** role/weight (what was in force at vote time was never recorded), flagged `BACKFILLED`. For votes on pending requests this equals what the old tally used, so there is no behaviour change at migration time. The immutability trigger on `ApprovalVote` is disabled for that single `UPDATE` and re-enabled immediately. **Atomicity was verified, not assumed:** a copy of the migration with an injected `SELECT 1/0` placed right after the `DISABLE TRIGGER` statement failed with `P3018`; afterwards the trigger's `tgenabled` was `O` (enabled), none of the new tables, enum or columns existed, and an `UPDATE` on `ApprovalVote` was still rejected — Prisma applies each migration file as one transaction.
- **Verified** by seeding a pre-Phase-1 database (including a pending request with a cyclic fallback pair, a terminal request and votes) and then applying the migration: chain truncated at the revisit, votes `BACKFILLED`, vote/level updates and a cycle-creating update all rejected afterwards, no drift.

**Rollback limits.** There is no automated down-migration. Dropping the new tables/columns/triggers is possible, but (a) the snapshot rows, revisions and vote-time attributes are *new historical facts* that would be lost; (b) the pre-Phase-1 application cannot insert votes into the new schema because `roleAtVote`/`weightAtVote` are `NOT NULL` without a default — rolling back the code therefore requires also dropping those constraints or columns; (c) requests created after the migration have no meaningful live-policy equivalent of their frozen rules. Take a database backup before applying to anything you care about.

---

## 10. Remaining risks and incomplete requirements

1. **Collusion is not prevented.** Separation of duties stops a *single* actor from authoring and approving. Two colluding admins (one edits, the other approves) are still possible; policy changes themselves still need only one admin. Two-person approval of policy changes is a Phase 3-style follow-up.
2. **The 24 h cooling-off window is a heuristic**, chosen to catch "edit, then a trivial second edit, then vote". Authors of older revisions are not blocked. The window is a code constant.
3. **Step-up is purpose-bound and single-use but not bound to the specific mutation payload** (the challenge is a server-generated random value, as in the existing step-up). A proof cannot be reused, but it is not a signature over "set weight to 9 for user X".
4. **Not covered by step-up:** service-account management (`/service-accounts`: create, credential issue/revoke, status). Account status changes *are* covered; an emergency suspension therefore also needs the actor's passkey. Invitations/enrollment tokens are covered (see §6) but through the older challenge purpose, whose challenge is shared with nothing else.
5. **Role/weight changes do not evict sockets** already in a request's room (re-checked on next join), unchanged from before.
6. **Votes carry over on escalation** and are re-evaluated under the new level's rules, including roles recorded on those votes that the new level may not list. This is pre-existing behaviour, now explicit; no policy change was made.
7. **Delete cascade.** Snapshot levels are protected against `UPDATE` but not `DELETE` (deleting a request cascades; nothing in the application deletes requests). A database owner can still bypass triggers — the Phase 4 audit-trust items are untouched.
8. **Audit chain clock ratchet** (observed, not fixed): audit timestamps are clamped to the tip's, so a row written under a wrong (future) clock holds every later timestamp at that value. Out of scope; noted for Phase 4.
9. **Frontend not exercised in a browser.** The client type-checks and builds, and the server enforces everything independently, but the passkey prompts for policy/user pages were not driven end-to-end. `PolicyManagement` also has no UI for the new 403 `STEP_UP_REQUIRED` code beyond the generic error text.
10. **Unrelated Phase items untouched:** deployment bootstrap, secret validation, dependency upgrades, rate-limit proxy config, CI.
11. **Legacy pending requests have no editor-conflict set** (§9, limitation).
12. **Environment.** The disposable verification container (`nf-audit-pg`, with its throwaway databases) was removed at the end. Docker Desktop (started during the previous phase) is still running, and your `novaforge-postgres-1` container is up and untouched — the Phase 1 migration has not been applied to it.

---

## 11. Git status

Branch `main`, base `5f3a2a6`. **No commit was made, nothing pushed, no history rewritten.** `server/prisma/migrations/migration_lock.toml` remains modified from before this work (line-endings only) and was not touched.

Modified: `client/src/lib/api.ts`, `client/src/pages/PolicyManagement.tsx`, `client/src/pages/UserManagement.tsx`, `server/prisma/schema.prisma`, `server/src/lib/{escalation,socketSecurity,stepUp}.ts`, `server/src/middleware/requireTrust.ts`, `server/src/routes/{actions,approvals,policies,users}.ts`, `server/test/testServer.ts` (shared helper), and the test files `approvals`, `audit`, `expiry-race`, `p0-4-decision-binding`, `p0-6-identity-trust`, `policies`, `socket-security`, `user-deletion`, `vote-eligibility-race` (each `*.test.ts`).

New (untracked): `client/src/lib/stepUp.ts`, `server/src/lib/governance.ts`, `server/src/lib/policySnapshot.ts`, `server/prisma/migrations/20261020100000_phase1_governance_integrity/`, `server/test/phase1-governance.test.ts`, this report, and the earlier `Docs/PROJECT_STATUS_AND_ROADMAP.md`.

Suggested review/commit split if you want small commits: (1) migration + schema + `policySnapshot.ts` + request creation/vote/escalation/socket changes + their test updates; (2) vote-time attributes; (3) `governance.ts` + policy/user routes + client + tests; (4) cycle guard.

---

## 12. Acceptance checklist

| Requirement | Status |
|---|---|
| T1 Snapshot captured at creation incl. quorum, min approvals, eligible roles, timeout, fallback chain | **PASS** |
| T1 Weighted rules: threshold in snapshot, weights frozen per vote | **PASS** |
| T1 Explicit fallback/escalation semantics, no history rewriting | **PASS** (§4) |
| T1 Voting, quorum, escalation, sockets, listings use the snapshot | **PASS** |
| T1 Legacy pending requests migrated and backfilled safely | **PASS** (§9; verified on seeded legacy data) |
| T1 No silent fallback to live policy for new requests | **PASS** (fail-closed 409 / deny) |
| T2 `roleAtVote` / `weightAtVote` recorded atomically with the vote | **PASS** |
| T2 Tally uses frozen attributes; regression tests | **PASS** |
| T2 DB-level immutability; backfill + documented limits | **PASS** |
| T3 Step-up + trust on policy, role, weight, status, delete, invitation and enrollment-token mutations, server-side | **PASS** (service-account management not covered, §10.4) |
| T3 Missing / invalid / expired / insufficient proof rejected | **PASS** (tested) |
| T3 Existing RBAC preserved | **PASS** |
| T3 Frontend completes the flow | **PASS** for build/typecheck; **BLOCKED** for browser verification (not run) |
| T3 Policy editor cannot approve governed requests, durable and race-safe | **PASS** (collusion by two actors out of scope, §10.1) |
| T3 Failed and successful governance operations audited | **PASS** |
| T3 Extra safeguards investigated (last super admin race) | **PASS** (implemented and tested) |
| T4 Multi-policy cycle detection on create/update | **PASS** |
| T4 Concurrent updates cannot create a cycle | **PASS** (API and raw SQL) |
| T4 Escalation terminates, fail-closed | **PASS** |
| T5 Additive, properly named migration; no reset/drop | **PASS** |
| T5 Schema validated against migrations | **PASS** (no drift) |
| T5 Rollback limitations documented; migration atomicity verified | **PASS** (§9) |
| T5 Legacy editor-conflict backfill | **PARTIAL** — legacy pending requests get no conflict set (§9) |
| T6 Tests 1–7 (real PostgreSQL) | **PASS** |
| T6 Test 8: all pre-existing suites still pass | **PASS** (with the documented test updates, §8) |
| Verify: server typecheck / Prisma validate / migrate on disposable DB / drift / full suite | **PASS** |
| Verify: client build | **PASS** |
| Verify: lint | **BLOCKED** — no lint configuration exists in the repo |
| Verify: frontend tests | **BLOCKED** — none exist |
| Applied to the user's existing database | **NOT DONE** (intentionally) |
