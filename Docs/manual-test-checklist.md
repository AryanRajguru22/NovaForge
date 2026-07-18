# NovaForge Manual Test Checklist

This document contains the manual QA test cases for every major feature of NovaForge.

---

# Authentication

## AUTH-001 – Register a New Passkey

### Preconditions
- User account does not already exist.

### Steps
1. Open the login page.
2. Click **Register Passkey**.
3. Enter name and email.
4. Complete passkey registration.

### Expected Result
- User account is created.
- Passkey is registered.
- Success message is displayed.

### Status

- [ ] Pass
- [ ] Fail

### Notes

---

## AUTH-002 – Login Using Passkey

### Preconditions
- Passkey already exists.

### Steps
1. Enter registered email.
2. Click Login.
3. Select passkey.
4. Complete biometric/PIN.

### Expected Result
- User is redirected to dashboard.

### Status

- [ ] Pass
- [ ] Fail

### Notes

---

## AUTH-003 – Login with Unknown Email

### Expected Result

User receives a clear error indicating that no account or passkey exists.

---

## AUTH-004 – Logout

### Steps

1. Login.
2. Logout.
3. Refresh page.

### Expected Result

User remains logged out.

---

## AUTH-005 – Session Persistence

### Expected Result

Refreshing the page should not require logging in again while the session is valid.

---

## AUTH-006 – TOTP Login

### Expected Result

Correct code logs in.

Incorrect code is rejected.

---

## AUTH-007 – Recovery Code Login

### Expected Result

Unused recovery code works exactly once.

Previously used recovery code is rejected.

---

## AUTH-008 – Error Handling

Verify the application displays user-friendly messages for:

- Invalid passkey
- Invalid TOTP
- Expired session
- Network failure

---

# Approval Engine

To be completed as approval-workflow functionality is implemented.

---

# Audit Trail

(To be completed once audit logging is finalized.)

---

# Overall Test Summary

| Feature | Status |
|----------|--------|
| Passkey Registration | ⏳ In Progress |
| Passkey Login | ⏳ In Progress |
| TOTP | ⏳ Pending |
| Recovery Codes | ⏳ Pending |
| Approval Engine | ⏳ Pending |
| Audit Trail | ⏳ Pending |
