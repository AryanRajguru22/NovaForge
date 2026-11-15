# NovaForge — Security Model, Findings and Limitations

Last reviewed: 2026-11-15, against the repository at the commit that introduced this file.

## 1. How to read the claims

Four different statements are easy to confuse. This document keeps them apart.

| Level | Meaning |
|---|---|
| **Implemented** | The code exists and is reachable. |
| **Tested** | An automated test exercises it against a real PostgreSQL database and would fail if the behaviour were removed (negative controls were run for the key ones). |
| **Independently verified** | Reviewed or attacked by someone other than the authors. **Nothing in this repository is independently verified.** No penetration test, third-party audit or formal verification has been performed. |
| **Production-ready** | Safe to run for real users with real consequences. **No** — see §5. |

## 2. What NovaForge protects, and against whom

| Asset | Threat considered | Control |
|---|---|---|
| Account takeover | Phished/stolen password | No passwords exist. Passkeys are origin-bound; TOTP/recovery are throttled fallbacks. |
| Session theft | Stolen cookie / refresh token | 15 min access token, rotating refresh token with family revocation on reuse, per-request DB liveness check, trust decay + step-up for sensitive writes. |
| Approval fraud | One person forcing an approval | Server-computed quorum, one signed vote per approver (DB unique), frozen policy, frozen voter weight/role, separation of duties, step-up on policy/role changes. |
| Approval races | Concurrent votes/expiry | Row locks + compare-and-swap + terminal-state trigger. |
| Evidence tampering | Editing history after the fact | Append-only, hash-chained audit log written in the same transaction as the change. |
| Information leak | Reading others' requests/events | Server-side authorisation on every REST route and Socket.io room; indistinguishable denial. |

### Trust assumptions (what the guarantees depend on)
1. **The database owner is trusted.** The application connects as the schema owner, so someone with
   that credential can disable triggers (`session_replication_role = replica` — the test suite itself
   does this) and rewrite rows *and* recompute a consistent hash chain. The chain is therefore
   **tamper-evident against ordinary application operations and against any party without that
   privilege**, not tamper-proof against a privileged operator. Detection of operator tampering
   requires an externally stored anchor (`GET /audit/head`); the endpoint and the verification
   parameter exist, but exporting and checking the anchor is **not automated**.
2. **TLS terminates in front of the server** and `RP_ORIGIN` is the real https origin in production.
3. **`TRUST_PROXY` equals the real number of proxies** (otherwise per-IP limits are shared or spoofable).
4. **Server secrets are kept secret and rotated by the operator** (`JWT_*`, `TOTP_ENCRYPTION_KEY`,
   identity signing key). There is no KMS/HSM integration.
5. **Single instance.** WebAuthn challenges and burst limits live in process memory.

### Non-repudiation, stated carefully
Each vote stores the WebAuthn assertion over a canonical statement of exactly what was approved.
That makes a vote *cryptographically bound* to a credential and a specific decision, and it can be
re-verified (`verifyStoredVoteEvidence`, used in tests). It is **not** legal non-repudiation: an
operator with database access could attach a credential to an account (the recovery script exists for
that purpose), and no API currently exports evidence for third-party re-verification.

## 3. Findings ledger

Re-triaged against the code at HEAD (the earlier audit in `PROJECT_STATUS_AND_ROADMAP.md` dated
2026-10-20 is partly out of date; its status here supersedes it).

| ID | Finding | Status | Evidence |
|---|---|---|---|
| F-01 | Governance plane (policy/role edits) ungoverned | **Fixed** | Policy snapshot, step-up + trust, separation of duties — `phase1-governance.test.ts` |
| F-02 | Placeholder secrets accepted silently | **Fixed** | `assertProductionConfiguration` (called in `index.ts`) — `env-config.test.ts` |
| F-03 | Fresh deployment cannot create first admin | **Fixed** | `src/cli/bootstrap-admin.ts` ships in `dist/` — `hardening.test.ts`, verified in a built container |
| F-04 | Audit not tamper-proof against DB owner; no anchoring | **Partially mitigated** | Terminal-state triggers added. Runtime/migration role split and automated anchor export **not done** (trust assumption 1). |
| F-05 | Single-instance assumptions | **Open (documented)** | In-memory challenges/limits; do not run more than one replica. |
| F-06 | Tally used current voter attributes | **Fixed** | `roleAtVote`/`weightAtVote` — `phase1-governance.test.ts` |
| F-07 | Fallback-policy cycles | **Fixed** | App lock + DB trigger — tested incl. concurrent raw SQL |
| F-08 | Vote evidence not exportable | **Open** | Evidence stored and verifiable in tests; no export endpoint or offline verifier. |
| F-09 | Rate limiting ineffective behind proxies; unbounded memory | **Fixed** | `TRUST_PROXY` documented and set in compose/`render.yaml`; nginx overwrites `X-Forwarded-For`; buckets capped — `hardening.test.ts` |
| F-10 | Audit coverage gaps | **Partially fixed** | Fallback-factor failures, governance refusals, OAuth events audited. Failed *passkey* logins and service-credential use are deliberately **not** audited (an unauthenticated write to the single global chain lock would be a denial-of-service lever). Throttling still bounds them. |
| F-11 | Dependency advisories | **Mostly fixed** | See §4. |
| F-12 | Last-super-admin race | **Fixed** | Recount under advisory lock — tested |
| F-13 | A single eligible REJECT/POSTPONE terminates a request | **Accepted design** | Veto semantics; an operator who wants otherwise must change policy semantics. |
| F-14 | Account enumeration | **Mostly fixed** | Passkey login options/verify now uniform. Accepted residual: a TOTP/recovery login for an account that *has disabled that method* returns a distinct 403 (intentional UX; throttled). |
| F-15 | Misc hardening | **Fixed** | Security headers, 100 kB body limit, boot path logging removed, bucket eviction. |
| F-16 | UV mismatch; brittle socket reconnect | **Fixed** | Login options now require UV (matches verify); client reconnects on transient errors. |

### New findings from this review
| Severity | Finding | Status |
|---|---|---|
| High | **The shipped `docker compose` demo stack could not boot**: the production-config check rejected the placeholder `.env` the README told users to copy. | Fix written (compose runs `NODE_ENV=development` explicitly; documented as non-production). The failure was reproduced against the old image; the fixed stack has **not yet been built and run end to end** (Docker was unavailable when this was written), so treat it as unverified until `docker compose -p <name> up --build` succeeds. |
| High | **OIDC sign-in dead-ended in the browser**: the server redirected unauthenticated users to `/oauth/signin`, a route the SPA did not have. | Fixed (`OAuthSignIn`, `oauthResume`; client tests). |
| Medium | Containers ran as **root**, had no HEALTHCHECK, and Node did not receive SIGTERM (no graceful shutdown). | Fixed. |
| Medium | `Dockerfile.render` build context had no root `.dockerignore` (host `node_modules` / `.env` could enter the image). | Fixed. |
| Low | Raw boot-time filesystem path logging. | Fixed. |

## 4. Dependency status

Production dependency audit (`npm audit --omit=dev`) — **0 critical, 0 high** on both packages.
Remaining, accepted with reasons:

| Package | Advisory | Why accepted |
|---|---|---|
| `@simplewebauthn/server` (low) | Attestation certificate-chain check | NovaForge requests `attestationType: "none"`; attestation chains are never evaluated. Fix needs a major upgrade (v14). |
| `qs` (moderate) | DoS in `qs.stringify` edge cases / `isBuffer` | Reached only through Express's query parser with a bounded 100 kB limit. No fixed release on the 6.x line yet. |
| `react-router` (moderate, client) | Open redirect via backslash / SSR issue | No server-side rendering; every `<Navigate>` target is a constant or a value validated against a strict pattern (`oauthResume.ts`). Fix needs v7. |

`zod` was upgraded 3 → 4 to close a high-severity memory-exhaustion advisory; the full suite passed
on the upgrade. Dev-only advisories (vitest/vite/esbuild toolchains) are not shipped and are not
gated in CI.

## 5. Production readiness

**Not production-ready.** The core engine is unusually rigorous for its size and is well tested, but:

* Nothing has been independently verified (§1).
* No monitoring, metrics, structured logging, alerting, or backup/restore procedure.
* Single instance only; no HA; no external audit anchoring; no DB role separation (F-04, F-05).
* Browser-level passkey UX has been exercised by automated tests with a software authenticator, not
  across real authenticators/devices/browsers.
* No consumer of approval outcomes exists, so approvals do not *do* anything downstream.
* No load or soak testing; all audited writes serialise on one chain-head row, which bounds throughput.

Suitable today for: local demonstration, evaluation, and as a reference implementation of the
patterns above.

## 6. Known limitations (complete list of things the product does not do)

* No outcome delivery (webhook/poll) for approved actions; no executor.
* No organisation/tenant model; one deployment is one trust domain.
* No automated audit-anchor export; no DB role split; no KMS/HSM.
* No evidence-export endpoint or offline verifier CLI.
* No email/push notifications, delegation, requester cancel, or pagination on list endpoints.
* No admin web UI for relying applications (OIDC clients, roles, assignments): the API exists
  (`/api/applications`, tested) and `scripts/iam.ts` provides the operator path.
* Failed passkey logins and service-credential use are not audit events (see F-10).
* The 5 s refresh grace window hands a holder of a *just-rotated* token the current valid token.
* Role/weight changes do not evict a socket already in a request room (rechecked on next join).
* Collusion of two administrators (one edits a policy, the other approves) is not prevented.
* CI cannot run the Pashupatastra cross-application end-to-end test (it needs the sibling repository);
  it runs locally when that repository is present and self-skips otherwise.

## 7. Reporting a vulnerability

Open a private security advisory on the GitHub repository, or contact the maintainers directly.
Please do not file public issues containing exploit details.
