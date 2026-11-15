# NovaForge Project Roadmap

Updated 2026-11-15. Authoritative detail: [SECURITY.md](./SECURITY.md) (findings, limitations) and
[ARCHITECTURE.md](./ARCHITECTURE.md) (what exists).

## Goals

Passwordless identity, quorum-based approval of sensitive actions with passkey-signed decisions, and a
tamper-evident audit trail, plus an OIDC provider so other applications can reuse the identity.

## Delivered

- [x] Passkey registration and sign-in; TOTP and recovery-code fallbacks with persistent throttling
- [x] Enrollment links, bootstrap CLI for the first administrator
- [x] Sessions: rotating refresh tokens, replay revocation, per-request liveness, trust decay and step-up
- [x] RBAC with server-side enforcement; governance changes need step-up
- [x] Approval engine: N-of-M, role-based, weighted; signed votes; concurrency-safe resolution
- [x] Per-request policy snapshots, frozen voter attributes, separation of duties, cycle prevention
- [x] Escalation and fail-closed expiry
- [x] Hash-chained, trigger-protected audit log with verification and anchor support
- [x] Socket.io authentication, room authorisation and revocation
- [x] OIDC provider (PKCE, ES256, JWKS, introspection, revocation) and per-application RBAC
- [x] Applications console (`/applications`) and OIDC browser sign-in resume
- [x] CI workflow, Docker hardening (non-root, health checks, graceful shutdown), client lint and tests
      (CI workflow and container changes are written but not yet exercised on GitHub Actions or a Docker build)

## Not done (see SECURITY.md §6 for the complete list)

| Item | Why it matters |
|---|---|
| Outcome delivery for approved actions (webhook/poll) | Approvals currently record decisions but trigger nothing. |
| Automated audit-anchor export + DB role separation | Needed for tamper-evidence against a privileged DB operator. |
| Vote-evidence export and offline verifier | Needed for third-party verification of signed votes. |
| Multi-instance support (shared challenge store, Socket.io adapter) | Required to scale beyond one replica. |
| Monitoring, structured logs, backups | Required before real users. |
| Independent security review | Nothing here has been externally verified. |

## Risks

| ID | Risk | Status |
|---|---|---|
| R-001 | Browser/authenticator compatibility can affect passkey demos. | Test on target hardware before presenting. |
| R-002 | Single-instance in-memory state. | Documented; run one replica. |
| R-003 | No external verification of the security claims. | Open. |
