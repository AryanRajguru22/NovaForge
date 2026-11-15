# NovaForge — Technical Architecture

This document describes what the code **does**, not what it aspires to. Every behaviour below is
implemented in the cited file and, where noted, exercised by an automated test against a real
PostgreSQL database. Limitations are in [SECURITY.md](./SECURITY.md).

## 1. System overview

```
Browser (React SPA) ──HTTPS──▶ nginx / Render edge ──▶ Express API (single process)
   │  passkey (WebAuthn)                                   │  Prisma ──▶ PostgreSQL 16
   └──────── Socket.io (cookie auth) ─────────────────────┘      (constraints + triggers)
Relying applications ── OIDC (code + PKCE) / service credentials ──▶ Express API
```

| Component | Technology | Notes |
|---|---|---|
| Client | React 18, TypeScript, Vite, Tailwind | `client/`. Talks to `/api/*` with httpOnly cookies. |
| Server | Node 20, Express 4, TypeScript (ESM) | `server/src/`. One process; zod validates every body. |
| Database | PostgreSQL 16 via Prisma 5 | Invariants are enforced by constraints/triggers, not only application code. |
| Real time | Socket.io 4 | Cookie-authenticated, per-request rooms, authorised on join. |
| Identity provider | OAuth 2.0 / OIDC (`server/src/routes/oauth.ts`) | ES256 tokens, JWKS, PKCE mandatory. |

The server is **single-instance by design** (in-memory WebAuthn challenges and burst rate limits;
see SECURITY.md).

## 2. Data model (invariants that matter)

Defined in `server/prisma/schema.prisma`; hand-written SQL lives in the migrations.

| Table | Invariant | Enforced by |
|---|---|---|
| `ApprovalVote` | one vote per approver per request | `@@unique([requestId, approverId])` |
| `ApprovalVote` | rows cannot be updated (incl. `roleAtVote`, `weightAtVote`) | `ApprovalVote_before_update_immutable` trigger |
| `SensitiveAction` | `type`, `payload`, `payloadDigest` immutable | `..._before_update_immutable_subject` trigger |
| `ApprovalRequest` / `SensitiveAction` | a decided status can never change | `*_terminal_status_guard` triggers (migration `20261115100000`) |
| `ApprovalRequestPolicyLevel` | frozen policy snapshot, update-immutable | `..._immutable` trigger |
| `ApprovalPolicy` | no fallback cycles, chain ≤ 5 | application advisory lock **and** `ApprovalPolicy_fallback_guard` trigger |
| `AuditLog` | append-only, strictly sequential, hash-linked | before/after-insert triggers, update/delete/truncate rejected |
| `Session` | one row = one refresh-token family | `currentRefreshTokenId` compare-and-swap |

Migrations are additive and never edited once applied. `prisma migrate diff` against a database
built from the migrations reports no drift (checked in CI).

## 3. Authentication

NovaForge is **passwordless**: there is no password to register, store or reset.

### 3.1 Accounts and enrollment
* Open self-registration is **off** (`ALLOW_OPEN_REGISTRATION`). Accounts are created by a
  SUPER_ADMIN invitation or the bootstrap CLI, each yielding a single-use **enrollment token**.
* Enrollment token (`lib/enrollment.ts`): 256-bit random, `nfenr_` prefix, 24 h TTL, only its
  SHA-256 is stored, redemption is an atomic conditional update, issuing a new token revokes the old.
* First administrator: `npm run bootstrap:admin` / `node dist/cli/bootstrap-admin.js`
  (`src/cli/bootstrap-admin.ts`). Refuses if any active SUPER_ADMIN exists; one transaction behind an
  advisory lock; audited. Test: `hardening.test.ts`.

### 3.2 WebAuthn / passkeys (`lib/webauthn.ts`, `routes/auth.ts`, `@simplewebauthn/server` v10)
* Registration/enrollment: challenge generated server-side, stored in the in-memory challenge store
  (**5-minute TTL, single use** — `takeChallenge` deletes on read), `userVerification: "required"`,
  `attestationType: "none"`. The relying-party ID and **exact origin** come from configuration
  (`RP_ID`, `RP_ORIGIN`) and are checked by the library on every ceremony.
* Login: `/auth/login/options` then `/auth/login/verify`. Signature verified against the stored
  public key; the **signature counter** must increase and is persisted; user verification is
  required. Unknown accounts and accounts without a passkey receive indistinguishable *decoy*
  options and fail with the same generic message (no account enumeration through this endpoint).
* The test suite uses a **real software authenticator** (`test/softAuthenticator.ts`) whose
  assertions are verified by the unmodified library — there is no verification bypass anywhere.

### 3.3 TOTP and recovery codes (fallback factors)
* Both are **fallbacks**, individually switchable per account (`PATCH /auth/preferences`).
* TOTP (`lib/totp.ts`, `otplib`): secret AES-256-GCM encrypted at rest (`TOTP_ENCRYPTION_KEY`),
  ±5 s clock tolerance, **replay guard** (`totpLastUsedStep` must strictly increase).
  Enrolling TOTP needs a *fresh passkey signature* (step-up), not just a session.
* Recovery codes: 10 codes, 80 bits each, **scrypt-hashed**, shown once, single-use via conditional
  delete; regenerating requires a fresh passkey step-up.
* Fallback guessing is bounded by a **persistent, row-locked per-account throttle**
  (`lib/authThrottle.ts`): 5 attempts, then 15 min lock doubling to 24 h. It cannot be raced with
  concurrent requests (tested). An in-memory per-IP/per-email burst limiter sits in front of it.

### 3.4 Step-up (`lib/stepUp.ts`, `lib/governance.ts`)
A purpose-bound, single-use passkey assertion with user verification, 5-minute challenge.
Required, **server-side**, for: TOTP enrollment, recovery-code regeneration, enrollment tokens and
invitations, every policy mutation, every user role/weight/status/delete change, and application
administration. Missing/invalid/replayed/expired/wrong-purpose proofs are rejected and audited.

## 4. Sessions and tokens

| Token | Lifetime | Where | Validation |
|---|---|---|---|
| Access JWT (HS256) | 15 min | httpOnly cookie | `iss`/`aud`/`alg`/`type` pinned; **every request** re-checks the `Session` row is live and the user `ACTIVE` |
| Refresh JWT (HS256, separate secret) | 30 days | httpOnly cookie | rotated on every use |

**Refresh-token rotation** (`lib/refreshRotation.ts`, 19 tests in `refresh-rotation.test.ts`):
* The `Session` row *is* the token family; the live token's `jti` is `currentRefreshTokenId`.
* Rotation is an atomic compare-and-swap on that column — of two concurrent refreshes with the same
  token exactly one wins.
* A just-rotated token is honoured for a **5 s grace window** (legitimate double-submit, e.g. two
  tabs) and returns the current token. This is a deliberate trade-off.
* A rotated-out token presented **outside** the grace window is treated as theft: the whole session
  (family) is deleted and `REFRESH_TOKEN_REUSE_DETECTED` + `SESSION_REVOKED` are audited atomically.
* Logout and `DELETE /auth/sessions/:id` delete the row; a still-unexpired access token stops working
  on its very next request because liveness is checked against the database.
* Disabling or deleting a user revokes their sessions and enrollment tokens and drops their sockets.
* Secrets, tokens and recovery codes are never logged.

### 4.1 Session trust (what it actually is)
`Session.trustLevel` starts at 100 and **decays 5 points per hour** since the last server
check-in; each check-in (`POST /auth/session/refresh`, which the client calls every 4 minutes) adds
back 5 (cap 100). Decay is computed on read (`lib/trust.ts`) so an idle tab cannot hold a stale high
value. Sensitive writes — creating an action, casting a vote, and every governance mutation —
require **effective trust ≥ 50** (`requireTrust`, `governanceTrust`), enforced on the server.

This is a **time-since-last-verification signal only**. It does *not* use device fingerprints,
IP/geolocation, behaviour or any external risk feed, and NovaForge does not claim to. Its meaning is
"how recently was this session proven alive?", which is a defensible, explainable quantity.

## 5. Authorization

Roles: `SUPER_ADMIN > ADMIN > SENIOR_APPROVER > APPROVER > MEMBER`.
* The role is **always re-read from the database** per request, never taken from a token claim.
* `requireAdmin` (policies), `requireSuperAdmin` (users, audit, service accounts, applications writes).
* Resource access to an approval request (`lib/approvalAccess.ts`): requester, a user whose role is
  eligible under the request's frozen policy, a voter, or SUPER_ADMIN. Everyone else receives a
  response indistinguishable from "not found".
* There is **no multi-tenant / organisation model**: one deployment is one trust domain.
  "Tenant isolation" in this product means isolation between *users and approval requests* (above),
  not between organisations.

## 6. Governance: the approval engine

### 6.1 Lifecycle
1. `POST /actions` (trust-gated) creates a `SensitiveAction` + `ApprovalRequest` in one transaction.
   The subject gets an immutable `payloadDigest` = SHA-256 of the RFC 8785 canonical JSON of
   `{type, payload}`. The **entire policy chain is snapshotted** into `ApprovalRequestPolicyLevel`
   rows (`lib/policySnapshot.ts`), so later policy edits cannot change an in-flight request.
2. `POST /approvals/:id/options` builds a canonical **decision statement** (request, action, subject
   digest, approver, decision, reason, nonce, validity window). The WebAuthn challenge is the
   SHA-256 of that statement.
3. `POST /approvals/:id/vote` verifies the assertion against that challenge, then — in **one
   transaction** — locks the request (`SELECT … FOR UPDATE`), re-derives the subject digest,
   reads the frozen policy level, re-checks the voter's eligibility (voter row `FOR SHARE`),
   inserts the vote with its evidence and `roleAtVote`/`weightAtVote`, recomputes the outcome,
   performs a `PENDING → terminal` compare-and-swap, and appends audit rows. Socket events are
   emitted only if this transaction won the transition.
4. The **server** computes quorum. The client never decides an outcome.

### 6.2 Quorum types
`N_OF_M` (count of approvals ≥ `minApprovals`), `ROLE_BASED` (distinct `roleAtVote` values among
approvers), `WEIGHTED` (sum of `weightAtVote` ≥ `minApprovals`). Tally uses attributes **frozen on
each vote**. A single eligible `REJECT` or `POSTPONE` ends the request (veto semantics — a
documented design choice).

### 6.3 Separation of duties, escalation, expiry
* The author of a policy revision captured by a request (or of any revision of it in the preceding
  24 h) cannot see it as pending or vote on it. Fixed at creation under a lock.
* Escalation (`lib/escalation.ts`, 5 s poller): when `expiresAt` passes, the request moves to the
  next **frozen** level by compare-and-swap (`escalationLevel`, `expiresAt` in the `WHERE`); after the
  last level it becomes `EXPIRED` (fail closed). Chains are finite (≤ 6 levels) and cycle-free.
* Policy create/update/delete, role/weight/status changes need step-up + trust (§3.4).

### 6.4 Concurrency evidence
Real-Postgres tests race genuinely concurrent HTTP requests: duplicate votes (`approvals.test.ts`),
quorum resolution (`concurrent-quorum.test.ts`), vote vs expiry (`expiry-race.test.ts`), vote vs
eligibility change (`vote-eligibility-race.test.ts`), weighted tallies, policy edit vs vote and
cycle creation (`phase1-governance.test.ts`), last-super-admin demotion, concurrent refresh and
replay (`refresh-rotation.test.ts`), concurrent fallback guessing (`p0-2-fallback-abuse.test.ts`).

### 6.5 What the engine does *not* do
Nothing consumes an `APPROVED` outcome: NovaForge records and proves decisions; it does not execute
the underlying action or call back a relying service. See SECURITY.md "Known limitations".

## 7. Tamper-evident audit log (`lib/audit.ts`)

* Every event row carries `seq`, id, timestamp, entity, event, actor, correlation id, metadata and
  `prevHash`; `hash = SHA-256(canonical JSON of those fields)` (v2 format).
* `AuditChainHead` is a singleton row; triggers enforce `seq = head.seq + 1` and
  `prevHash = head.hash`, and reject UPDATE/DELETE/TRUNCATE. Appends serialise on the head row.
* Every audited write uses `auditedTransaction`: the state change and its audit row commit
  **atomically** — a sensitive operation cannot succeed while its audit write fails (the whole
  transaction rolls back; if the chain tip does not match the head, appends refuse with
  `AuditIntegrityError`).
* `GET /audit/verify` (SUPER_ADMIN) walks the chain in a repeatable-read snapshot and reports the
  first break; `GET /audit/head` + `anchorSeq`/`anchorHash` allow comparing against an externally
  stored value. Tests cover modified payload/hash, deleted (gap), reordered and forked rows.

**Guarantee:** ordinary application operations cannot silently rewrite history, and modification by
anyone *without* the ability to disable triggers is detected. **Not** guaranteed: a database owner
can disable triggers and recompute a consistent chain; detecting that requires an externally stored
anchor (supported, not automated). See SECURITY.md.

## 8. Real-time security (`lib/socketSecurity.ts`)

* Handshake (`io.use`): cookie access token verified **and** its session confirmed live; otherwise
  `Authentication required`.
* `join-challenge`: the id must be a UUID; the request, its frozen policy level and the user are
  re-read; access is decided by the same function as the REST API; a denied join is
  indistinguishable from a non-existent request. No room is ever created for a denied join.
* A 60 s sweep disconnects sockets whose session died; disabling/deleting a user disconnects them
  immediately.
* Tested in `socket-security.test.ts` (16 tests): unauthenticated, forged, revoked, cross-request
  and cross-user isolation, role/policy changes on next join.
* The client stops reconnecting only on an authentication rejection; transient failures use
  Socket.io's built-in backoff.

## 9. Identity provider (OIDC) and service identities

* Authorization-code flow, **PKCE S256 mandatory**, `state` and `nonce` required, **byte-exact**
  redirect-URI match (no redirect on mismatch), single-use 60 s codes (atomic; replay revokes the
  grant), ES256 ID/access tokens, JWKS at `/.well-known/jwks.json`, refresh-token rotation with
  reuse detection, RFC 7662 introspection, RFC 7009 revocation, RP-initiated logout, and a
  `/api/v1/authz/check` decision API. Per-application roles/permissions/assignments are administered
  through `/api/applications` (SUPER_ADMIN, step-up) or `scripts/iam.ts`.
* Browser leg: an unauthenticated `/api/oauth/authorize` redirects to `/oauth/signin`; the SPA
  (`pages/OAuthSignIn.tsx`, `lib/oauthResume.ts`) completes a normal sign-in and resumes. Only the
  query string is carried; the destination path is constant; the resume value expires after 10 min.
* Service accounts (`nfsvc_<id>.<secret>`, SHA-256 stored, scoped) request short-lived ES256 identity
  assertions at `/api/internal/*`.

## 10. HTTP hardening

`securityHeaders` (CSP, `X-Content-Type-Options`, frame denial, referrer/permissions policy, HSTS in
production), CORS pinned to `RP_ORIGIN` for the SPA API (open, credential-less CORS only for
discovery/JWKS/token/userinfo), `SameSite=Lax` httpOnly cookies (`Secure` when `RP_ORIGIN` is https),
JSON-only bodies with a 100 kB limit, generic 500s, zod validation, per-route rate limits
(memory-bounded) and DB-backed account throttles. `TRUST_PROXY` must equal the number of proxies in
front of the server (see README).

## 11. Deployment

| Artifact | Purpose |
|---|---|
| `docker-compose.yml` | **Local demo**: Postgres + API + nginx client, plain HTTP, `NODE_ENV=development`. |
| `server/Dockerfile`, `client/Dockerfile` | Multi-stage, runtime has no dev dependencies; server runs as non-root with a HEALTHCHECK on `/ready`. |
| `Dockerfile.render` | Combined single-origin image (API serves the SPA) for Render. |
| `.github/workflows/ci.yml` | Prisma validate/migrate/drift, typecheck, build, server tests (Postgres 16), client lint/test/build, `npm audit`, Docker builds. |

`/health` is liveness; `/ready` checks the database. The server handles SIGTERM/SIGINT gracefully
(stops timers, closes sockets and the HTTP server, disconnects Prisma, 10 s deadline).

## 12. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Server exits: `Refusing to start in production with unsafe configuration` | Production needs real secrets (≥ 32 chars, not placeholders, access ≠ refresh) and `IDENTITY_*` + https `RP_ORIGIN`. See `server/.env.example`. |
| Passkey prompt fails / "origin" errors | `RP_ID`/`RP_ORIGIN` must exactly match the browser's origin (scheme, host, port). |
| Everyone gets 429 | `TRUST_PROXY` not set behind a proxy, so all clients share one IP. Set it to the proxy count. |
| Logins break after a restart | Challenges are in memory (5 min); a restart mid-ceremony invalidates it. Retry. |
| `/login?enroll=…` says expired/used | Tokens are single-use, 24 h. Issue a new one (admin UI or `scripts/create-enrollment-token.ts`). |
| No administrator on a fresh install | `npm run bootstrap:admin -- --email … --name …` (or `docker compose exec server node dist/cli/bootstrap-admin.js …`). |
| Audit verify reports a break | Treat as an integrity incident: compare `/audit/head` with your external anchor and restore from backup if rows were altered. |
