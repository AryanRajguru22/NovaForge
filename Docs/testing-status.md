# NovaForge Testing Status

## Verified capabilities

| Area | Status | Evidence |
|---|---|---|
| Passkey authentication | Verified | Registration and sign-in flows are implemented and type-checked. |
| TOTP fallback | Verified | Enrollment and fallback login are implemented. |
| Recovery codes | Verified | Generation and single-use redemption are implemented. |
| Login-method controls | Verified | Real HTTP smoke test confirmed TOTP is blocked when disabled and works again after re-enabling. |
| Audit integrity | Verified | The audit hash chain validates after preference changes. |
| Session management | Implemented | Session listing, revocation, and trust refresh are available. |
| Approval engine | In progress | Validate once its active implementation workstream is merged. |

## Manual regression checklist

- [ ] Register and sign in with a passkey.
- [ ] Enroll TOTP and complete fallback sign-in.
- [ ] Generate and redeem a recovery code.
- [ ] Disable and re-enable each enrolled fallback login method.
- [ ] Revoke a non-current session.
- [ ] Verify the audit chain after state-changing actions.
- [ ] Exercise the approval workflow after integration is complete.

## Test artifacts

- `manual-test-checklist.md` contains repeatable manual test cases.
- `chaos-test-matrix.md` records resilience scenarios.
- `github-issue-template.md` provides a consistent issue report format.
