# NovaForge Chaos Test Matrix

This document records how NovaForge behaves under failure conditions.

| ID | Scenario | Expected Behaviour | Status | Notes |
|----|----------|--------------------|--------|-------|
| CT-001 | Internet disconnect during passkey registration | User receives a friendly error and can retry | ⏳ Pending | |
| CT-002 | Internet disconnect during login | Login fails gracefully without crashing | ⏳ Pending | |
| CT-003 | Refresh browser during login | User returns to a consistent state | ⏳ Pending | |
| CT-004 | Refresh browser during approval | Approval request is not duplicated | ⏳ Pending | |
| CT-005 | Approver goes offline | System escalates or waits according to policy | ⏳ Pending | |
| CT-006 | Server restart during active session | User can continue or is asked to re-authenticate cleanly | ⏳ Pending | |
| CT-007 | Invalid TOTP entered | Login is rejected with a clear error | ⏳ Pending | |
| CT-008 | Reuse a recovery code | Recovery code is rejected | ⏳ Pending | |
| CT-009 | Duplicate approval submission | Only one approval is recorded | ⏳ Pending | |
| CT-010 | Browser closed during approval | No partial approval is recorded | ⏳ Pending | |
| CT-011 | Session expires during sensitive action | User is prompted to authenticate again | ⏳ Pending | |
| CT-012 | Audit log unavailable | Action fails safely or logs when service recovers | ⏳ Pending | |

---

## Summary

- Total scenarios: 12
- Passed: 0
- Failed: 0
- Pending: 12

Update this table as features are completed and tested.