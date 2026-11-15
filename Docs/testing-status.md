# NovaForge Testing Status

Updated 2026-11-15. "Verified" here means an automated test against a real PostgreSQL database passes;
it does **not** mean independently audited (see [SECURITY.md](./SECURITY.md)).

## Automated suites

| Suite | Command | Result at last full run |
|---|---|---|
| Server (Vitest, real PostgreSQL 16) | `cd server && npm test` | 32 files, 341 tests, all passing (2026-11-15, native PostgreSQL 16.15; see [FINAL_RELEASE_READINESS_REPORT.md](./FINAL_RELEASE_READINESS_REPORT.md)) |
| Client (Vitest + Testing Library, jsdom) | `cd client && npm test` | 4 files, 35 tests, all passing |
| Client lint | `cd client && npm run lint` | clean, no rules disabled |
| Server typecheck | `cd server && npx tsc -p tsconfig.json --noEmit` | clean |
| Client typecheck + production build | `cd client && npm run build` | clean |
| Schema vs migrations | `prisma migrate diff … --exit-code` | no drift |

Server tests use a disposable database (see the README). One file, `pashupatastra-e2e`, drives a second
real application and self-skips when the sibling repository is absent (so it does not run in CI).

## Verified capabilities

| Area | Status | Where |
|---|---|---|
| Passkey registration / login (real WebAuthn verification) | Verified | `auth-preferences`, `p0-1-enrollment`, `hardening` |
| Login-option enumeration resistance, UV alignment | Verified | `hardening` |
| TOTP (encryption, tolerance, replay, enrollment step-up) | Verified | `totp-*`, `p0-2-fallback-abuse` |
| Recovery codes (hashed, single-use, bounded guessing) | Verified | `p0-2-fallback-abuse` |
| Refresh rotation, replay revocation, concurrent refresh | Verified | `refresh-rotation` (19) |
| Session revocation and trust decay/gating | Verified | `sessions`, `trust-*` |
| RBAC and resource access | Verified | `require-admin`, `p0-3-action-access` |
| Approval quorum: N-of-M, role-based, weighted | Verified | `approvals`, `weighted-quorum`, `policies` |
| Duplicate / concurrent votes, vote-vs-expiry, eligibility races | Verified | `approvals`, `concurrent-quorum`, `expiry-race`, `vote-eligibility-race` |
| Decision-bound signed votes and replay | Verified | `p0-4-decision-binding` (34) |
| Policy snapshots, step-up, separation of duties, cycles | Verified | `phase1-governance` (27) |
| Escalation | Verified | `escalation`, `phase1-governance` |
| Terminal-state DB guard | Verified | `hardening` (with negative control) |
| Audit chain: tamper, gap, reorder, fork, anchor | Verified | `audit` (30) |
| Socket.io authn/authz, isolation, revocation | Verified | `socket-security` (16) |
| OIDC: PKCE, redirect matching, code/refresh replay, introspection | Verified | `oauth-oidc` |
| Service identities and assertions | Verified | `p0-6-identity-trust`, `identity-assertion-trust` |
| Production configuration check | Verified | `env-config` |
| First-admin bootstrap | Verified | `hardening` |
| Rate-limiter memory bound | Verified | `hardening` |
| OIDC sign-in resume, route guards, single-flight token refresh | Verified | client tests |

## Not covered by automation

* Real browsers and real authenticators (platform biometrics, security keys); the suites use a software
  authenticator whose assertions are verified by the unmodified WebAuthn library.
* Load, soak and failover behaviour.
* The Pashupatastra cross-application test in CI.

## Manual checks

`manual-test-checklist.md` lists repeatable manual cases; `chaos-test-matrix.md` records resilience
scenarios; `github-issue-template.md` is the defect report format.
