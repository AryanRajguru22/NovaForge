# NovaForge Final Release Readiness Report

Date: 2026-11-15. Baseline commit before this report: `2df1180`.

**Classification: demonstration-ready.** Not controlled-pilot-ready, not deployment-verified, not
production-ready. The reasons are in sections 5, 6, 7 and 9.

## 1. Architecture (summary)

Node/Express + Prisma + PostgreSQL 16 server, React/Vite client, Socket.io. See
[ARCHITECTURE.md](./ARCHITECTURE.md). Single instance only.

## 2. Verified features (automated, real PostgreSQL)

Passkey sign-in with enumeration-resistant login options; TOTP and recovery-code fallbacks with
persistent throttling; rotating refresh tokens with replay revocation; session revocation and trust
gating; RBAC; approval engine (N-of-M, role-based, weighted, signed votes, concurrency and expiry races,
escalation, separation of duties); hash-chained audit log with tamper/gap/reorder/fork detection;
Socket.io authentication and room authorisation; OIDC provider (PKCE, ES256, JWKS, introspection,
revocation) with per-application RBAC; first-admin bootstrap CLI; terminal-status database guard.

Per-feature test mapping: [testing-status.md](./testing-status.md).

### Features named in the release brief that this repository does not contain

Missions, budgets, capability delegation/attenuation/cascading revocation, crash recovery,
duplicate-job protection, task cancellation, project-membership isolation, deployment/merge workflows,
and a six-workspace UI (Overview, Authority, Missions, Transactions, Security, Evidence) do **not** exist
in this codebase (searched `server/src`, `server/prisma/schema.prisma`, `client/src`). They were not
tested and are not claimed. The client has login, approvals, audit log, policies, users, applications and
settings pages.

## 3. Test results (this round, 2026-11-15)

| Check | Result |
|---|---|
| Server suite (`cd server && npm test`, native PostgreSQL 16.15) | 32 files, 341 passed, 0 failed, 0 skipped |
| Client suite (`cd client && npm test`) | 4 files, 35 passed, 0 failed |
| Server typecheck (`tsc --noEmit`) | clean |
| Client lint (`npm run lint`) | clean, no rules disabled |
| Client production build | clean |
| Dependency audit, gate `--audit-level=high` (server and client, production deps) | no high/critical; moderate findings remain (qs, react-router, simplewebauthn low) |

One flaky assertion was found and corrected this round: the OIDC test "allows only one of many
concurrent redemptions of the same code" failed in about 1 of 6 runs with **zero** successes. Cause:
the concurrent duplicates are treated as a replay (RFC 6749 4.1.2) and revoke the grant, which can reach
the winning request before it issues tokens. That fails closed and is not a vulnerability. The test now
asserts the real guarantee: at most one redemption succeeds, every other response is a 400
`invalid_grant`, no request errors, and the code cannot be redeemed again. Six consecutive isolated runs
and the full suite passed afterwards. No security assertion elsewhere was changed.

## 4. PostgreSQL verification

Native PostgreSQL 16.15 (embedded-postgres, port 55432). Fresh-database `prisma migrate deploy` applies
all migrations including `terminal_status_guard`; `prisma migrate diff` reports no drift; a negative
control (triggers dropped) failed four guard tests earlier in the work. **This is not the Docker
PostgreSQL.** Upgrade-in-place against a pre-populated database and restart persistence were not
separately exercised beyond what the suites cover.

## 5. Docker Compose verification: BLOCKED

Docker Desktop's engine did not start (backend process reports running, engine pipe never appears, the
`docker-desktop` WSL distro stays stopped, a clean `docker desktop stop` times out; C: is nearly full).
`docker compose config` validates the file syntax only. **Nothing below was run:** image builds, container
start, in-container migrations, health and readiness through the stack, in-container first-admin
bootstrap, graceful shutdown on `docker stop`, persistence across container restart.

What was run natively instead (not a substitute): the built server (`dist/index.js`) against a freshly
migrated database with compose-equivalent environment: `/health` 200, `/ready` ready, bootstrap CLI created
the first SUPER_ADMIN and refused a second run, protected routes returned 401 unauthenticated, login
options identical for a real and an unknown address, security headers present, no tokens or credentials
in the server log. Graceful SIGTERM shutdown could not be exercised on Windows.

Before the compose fix, the README's compose stack could not boot (the production-config check rejected
the placeholder `.env`); that was reproduced. The fix (explicit `NODE_ENV=development`, documented as
non-production) is unverified end to end.

## 6. Browser and passkey verification: NOT DONE

All passkey tests use a software authenticator whose assertions are verified by the unmodified WebAuthn
library. No real browser prompt, platform biometric or hardware security key was exercised, and none is
claimed. Needs a manual run on the demonstration hardware (see `manual-test-checklist.md`).

CSRF: there is no CSRF token. Mutations rely on `SameSite=Lax` session cookies, JSON-only bodies and CORS
restricted to the application origin. This design was reviewed but **not** probed with a cross-site
request test. Same-site (sibling subdomain) attackers are out of scope of that defence.

## 7. CI

`.github/workflows/ci.yml` is written (PostgreSQL 16 service, migrate and drift check, typecheck, build,
server tests, audit gate, client lint/test/build, docker builds). It has **not** executed on GitHub
Actions at the time of writing. Do not treat it as passing until the first run is seen.

## 8. Known limitations and their gating

| Limitation | Demo | Controlled pilot | Production |
|---|---|---|---|
| Approval outcomes trigger nothing downstream | ok if stated | blocks if outcomes must act | blocks |
| Single instance, in-memory challenge and rate state | ok | ok with one replica | blocks scaling |
| Audit chain is tamper-evident, not tamper-proof (no DB role split, no automated anchor export) | ok | needs external anchoring | blocks |
| No monitoring, structured logs, backups or restore drill | ok | blocks | blocks |
| Docker/Compose and CI unverified | ok with caveat | blocks | blocks |
| Real-browser / hardware-key passkey testing | needs one manual pass | blocks | blocks |
| No independent security review | ok | blocks | blocks |

None of these were fixed in this round (no feature work was in scope). Details: [SECURITY.md](./SECURITY.md).

## 9. Deployment requirements before any pilot

Working Docker run of the compose stack and images; a green GitHub Actions run; manual passkey test on
target hardware; external audit-anchor export; backups with a tested restore; monitoring and structured
logging; a decision on approval-outcome delivery; independent review.

## 10. Git

See the final report for hashes; this file is committed on top of `2df1180`. The DevOps-Tally remote
(`main` at `ca576c6`, an ancestor of this branch) was inspected read-only and **not** pushed to.
