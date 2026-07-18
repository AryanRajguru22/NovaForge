# NovaForge Project Roadmap

## Goals

NovaForge provides passwordless-first authentication, controlled fallback login methods, tamper-evident auditing, and configurable approval policies for sensitive actions.

## Current workstreams

| Workstream | Status | Focus |
|---|---|---|
| Identity | Complete | Passkeys, TOTP, recovery codes, sessions, and login-method controls |
| Approval engine | In progress | Policy evaluation, requests, and voting workflows |
| Audit and security | In progress | Hash-chain integrity and sensitive-action protections |
| Quality assurance | In progress | Manual, failure-mode, and end-to-end validation |
| Demo preparation | In progress | Demo flow, judge narrative, and final review |

## Delivery checklist

- [x] Passkey registration and sign-in
- [x] TOTP enrollment and fallback sign-in
- [x] Recovery-code generation and single-use redemption
- [x] User-controlled fallback login availability
- [x] Session management and trust-level refresh
- [x] Tamper-evident audit logging
- [ ] Approval policy configuration
- [ ] Approval request and vote workflow
- [ ] End-to-end demo rehearsal
- [ ] Final release review

## Current risks

| ID | Risk | Status |
|---|---|---|
| R-001 | Browser and authenticator compatibility can affect passkey demos. | Monitor during rehearsal |
| R-002 | Approval-workflow integration remains dependent on the active implementation workstream. | In progress |
| R-003 | Final demo requires repeatable local PostgreSQL and browser setup. | Validate before presentation |
