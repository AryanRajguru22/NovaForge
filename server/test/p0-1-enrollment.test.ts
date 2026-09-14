import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import {
  startTestServer,
  stopTestServer,
  apiRequest,
  createUserWithToken,
  addMockPasskey,
  authenticatorFor,
  cleanupUsers,
  runSuffix,
} from "./testServer.js";
import { SoftAuthenticator } from "./softAuthenticator.js";
import { prisma } from "../src/lib/prisma.js";
import { resetRateLimitBuckets } from "../src/middleware/rateLimit.js";

// P0-1: account takeover through registration.
//
// Attack: the attacker knows a victim's email (e.g. a SUPER_ADMIN's) and runs
// the public registration ceremony with their OWN authenticator, hoping the
// resulting credential is attached to the victim's account. Every attempt
// below uses a real software authenticator and real WebAuthn verification.

describe("P0-1: credentials can't be enrolled into an existing account by knowing its email", () => {
  const emails = {
    superAdmin: `p01-super-${runSuffix}@example.com`,
    otherSuper: `p01-super2-${runSuffix}@example.com`,
    member: `p01-member-${runSuffix}@example.com`,
    admin: `p01-admin-${runSuffix}@example.com`,
    newcomer: `p01-newcomer-${runSuffix}@example.com`,
    invited: `p01-invited-${runSuffix}@example.com`,
    recovered: `p01-recovered-${runSuffix}@example.com`,
  };
  let superAdmin: { id: string; token: string };
  let admin: { id: string; token: string };
  let member: { id: string; token: string };

  const passkeyCount = (userId: string) => prisma.credential.count({ where: { userId, type: "PASSKEY" } });

  async function stepUpResponse(user: { id: string; token: string }) {
    const options = await apiRequest("/users/step-up/options", { method: "POST", token: user.token });
    expect(options.status).toBe(200);
    return authenticatorFor(user.id).createAssertion(options.data.challenge);
  }

  async function issueEnrollmentToken(targetUserId: string): Promise<string> {
    const response = await stepUpResponse(superAdmin);
    const res = await apiRequest(`/users/${targetUserId}/enrollment-token`, { method: "POST", token: superAdmin.token, body: { response } });
    expect(res.status).toBe(201);
    return res.data.token as string;
  }

  async function enroll(token: string, authenticator: SoftAuthenticator) {
    const options = await apiRequest("/auth/enroll/options", { method: "POST", body: { token } });
    if (options.status !== 200) return options;
    return apiRequest("/auth/enroll/verify", {
      method: "POST",
      body: { token, response: authenticator.createRegistrationResponse(options.data.options.challenge) },
    });
  }

  async function passkeyLogin(email: string, authenticator: SoftAuthenticator) {
    const options = await apiRequest("/auth/login/options", { method: "POST", body: { email } });
    if (options.status !== 200) return options;
    return apiRequest("/auth/login/verify", {
      method: "POST",
      body: { email, response: authenticator.createAssertion(options.data.challenge) },
    });
  }

  beforeAll(async () => {
    await startTestServer();
    const s = await createUserWithToken({ email: emails.superAdmin, role: "SUPER_ADMIN" });
    superAdmin = { id: s.user.id, token: s.token };
    await addMockPasskey(superAdmin.id);
    await createUserWithToken({ email: emails.otherSuper, role: "SUPER_ADMIN" });
    const a = await createUserWithToken({ email: emails.admin, role: "ADMIN" });
    admin = { id: a.user.id, token: a.token };
    await addMockPasskey(admin.id);
    const m = await createUserWithToken({ email: emails.member, role: "MEMBER" });
    member = { id: m.user.id, token: m.token };
    await addMockPasskey(member.id);
  });

  afterEach(() => {
    delete process.env.ALLOW_OPEN_REGISTRATION;
    resetRateLimitBuckets();
  });

  afterAll(async () => {
    await cleanupUsers(Object.values(emails));
    await stopTestServer();
  });

  describe("attacker knows the victim's email", () => {
    it("with self-registration disabled (the default), the ceremony can't even start", async () => {
      const attacker = new SoftAuthenticator();
      const options = await apiRequest("/auth/register/options", { method: "POST", body: { email: emails.superAdmin, name: "Attacker" } });
      expect(options.status).toBe(403);

      const verify = await apiRequest("/auth/register/verify", {
        method: "POST",
        body: { email: emails.superAdmin, response: attacker.createRegistrationResponse("Zm9yZ2VkLWNoYWxsZW5nZQ") },
      });
      expect(verify.status).toBe(403);
      expect(await passkeyCount(superAdmin.id)).toBe(1);
      expect(await prisma.credential.findUnique({ where: { credentialId: attacker.credentialId } })).toBeNull();
    });

    it("with self-registration enabled, an existing SUPER_ADMIN email is refused and no credential is attached", async () => {
      process.env.ALLOW_OPEN_REGISTRATION = "true";
      const attacker = new SoftAuthenticator();
      const before = await prisma.user.findUniqueOrThrow({ where: { id: superAdmin.id } });

      for (const variant of [emails.superAdmin, emails.superAdmin.toUpperCase(), `  ${emails.superAdmin}  `]) {
        const options = await apiRequest("/auth/register/options", { method: "POST", body: { email: variant, name: "Attacker" } });
        expect(options.status).toBe(409);
        expect(options.data.challenge).toBeUndefined();
      }

      // Skipping options and submitting a self-made registration response directly.
      const verify = await apiRequest("/auth/register/verify", {
        method: "POST",
        body: { email: emails.superAdmin, response: attacker.createRegistrationResponse("YXR0YWNrZXItY2hvc2Vu") },
      });
      expect(verify.status).toBe(400);

      expect(await passkeyCount(superAdmin.id)).toBe(1);
      expect(await prisma.credential.findUnique({ where: { credentialId: attacker.credentialId } })).toBeNull();
      const after = await prisma.user.findUniqueOrThrow({ where: { id: superAdmin.id } });
      expect(after.role).toBe("SUPER_ADMIN");
      expect(after.name).toBe(before.name);
      // The victim's own passkey still works, and the attacker's can't sign in as the victim.
      expect((await passkeyLogin(emails.superAdmin, authenticatorFor(superAdmin.id))).status).toBe(200);
      expect((await passkeyLogin(emails.superAdmin, attacker)).status).toBe(400);
    });

    it("a challenge obtained for a new email can't be redirected onto the victim's account", async () => {
      process.env.ALLOW_OPEN_REGISTRATION = "true";
      const attacker = new SoftAuthenticator();
      const decoyEmail = `p01-decoy-${runSuffix}@example.com`;
      const options = await apiRequest("/auth/register/options", { method: "POST", body: { email: decoyEmail, name: "Decoy" } });
      expect(options.status).toBe(200);

      const verify = await apiRequest("/auth/register/verify", {
        method: "POST",
        body: { email: emails.member, response: attacker.createRegistrationResponse(options.data.challenge) },
      });
      expect(verify.status).toBe(400);
      expect(await passkeyCount(member.id)).toBe(1);
      expect(await prisma.user.findUnique({ where: { email: decoyEmail } })).toBeNull();
    });

    it("the attacker can't mint an enrollment link: MEMBER and ADMIN are forbidden, and SUPER_ADMIN needs a fresh passkey step-up", async () => {
      const asMember = await apiRequest(`/users/${superAdmin.id}/enrollment-token`, { method: "POST", token: member.token, body: { response: {} } });
      expect(asMember.status).toBe(403);
      const asAdmin = await apiRequest(`/users/${superAdmin.id}/enrollment-token`, { method: "POST", token: admin.token, body: { response: {} } });
      expect(asAdmin.status).toBe(403);

      // A stolen super-admin session cookie alone (no passkey signature) is not enough.
      const noStepUp = await apiRequest(`/users/${member.id}/enrollment-token`, {
        method: "POST",
        token: superAdmin.token,
        body: { response: new SoftAuthenticator().createAssertion("bm8tY2hhbGxlbmdl") },
      });
      expect(noStepUp.status).toBe(400);
      expect(await prisma.enrollmentToken.count({ where: { userId: member.id } })).toBe(0);
    });

    it("guessed, malformed, or expired enrollment tokens are rejected", async () => {
      const attacker = new SoftAuthenticator();
      for (const token of ["nfenr_" + "A".repeat(43), "not-a-token", ""]) {
        const res = await enroll(token, attacker);
        expect(res.status).toBe(400);
      }

      const token = await issueEnrollmentToken(member.id);
      await prisma.enrollmentToken.updateMany({ where: { userId: member.id, usedAt: null }, data: { expiresAt: new Date(Date.now() - 1000) } });
      expect((await enroll(token, attacker)).status).toBe(400);
      expect(await passkeyCount(member.id)).toBe(1);
    });
  });

  describe("legitimate enrollment", () => {
    it("a super admin (after step-up) issues a single-use link that adds a passkey to the target account", async () => {
      const { user } = await createUserWithToken({ email: emails.recovered, role: "APPROVER" });
      const token = await issueEnrollmentToken(user.id);
      expect(token).toMatch(/^nfenr_/);
      const stored = await prisma.enrollmentToken.findFirstOrThrow({ where: { userId: user.id } });
      expect(stored.tokenHash).not.toContain(token.slice(6));

      const device = new SoftAuthenticator();
      const res = await enroll(token, device);
      expect(res.status).toBe(200);
      expect(await passkeyCount(user.id)).toBe(1);
      expect((await passkeyLogin(emails.recovered, device)).status).toBe(200);

      // Single use.
      const reuse = await enroll(token, new SoftAuthenticator());
      expect(reuse.status).toBe(400);
      expect(await passkeyCount(user.id)).toBe(1);

      const events = await prisma.auditLog.findMany({ where: { entityId: user.id, event: { in: ["ENROLLMENT_TOKEN_ISSUED", "PASSKEY_REGISTERED"] } } });
      expect(events.map((e) => e.event).sort()).toEqual(["ENROLLMENT_TOKEN_ISSUED", "PASSKEY_REGISTERED"]);
    });

    it("issuing a new link revokes the previous one", async () => {
      const first = await issueEnrollmentToken(member.id);
      const second = await issueEnrollmentToken(member.id);
      expect((await enroll(first, new SoftAuthenticator())).status).toBe(400);
      expect((await enroll(second, new SoftAuthenticator())).status).toBe(200);
    });

    it("concurrent redemptions of one link add exactly one credential", async () => {
      const { user } = await createUserWithToken({ email: `p01-race-${runSuffix}@example.com`, role: "MEMBER" });
      const token = await issueEnrollmentToken(user.id);
      const options = await apiRequest("/auth/enroll/options", { method: "POST", body: { token } });
      const [a, b] = [new SoftAuthenticator(), new SoftAuthenticator()];
      const results = await Promise.all(
        [a, b].map((device) =>
          apiRequest("/auth/enroll/verify", {
            method: "POST",
            body: { token, response: device.createRegistrationResponse(options.data.options.challenge) },
          }),
        ),
      );
      expect(results.filter((r) => r.status === 200)).toHaveLength(1);
      expect(await passkeyCount(user.id)).toBe(1);
      await cleanupUsers([`p01-race-${runSuffix}@example.com`]);
    });

    it("an invitation creates the account with its role and a link only that invitee can redeem", async () => {
      const response = await stepUpResponse(superAdmin);
      const invite = await apiRequest("/users/invitations", {
        method: "POST",
        token: superAdmin.token,
        body: { email: emails.invited, name: "Invited Authority", role: "SENIOR_APPROVER", response },
      });
      expect(invite.status).toBe(201);
      expect(invite.data.user.role).toBe("SENIOR_APPROVER");

      const device = new SoftAuthenticator();
      expect((await enroll(invite.data.token, device)).status).toBe(200);
      expect((await passkeyLogin(emails.invited, device)).status).toBe(200);

      // Inviting an existing email doesn't hijack it.
      const again = await apiRequest("/users/invitations", {
        method: "POST",
        token: superAdmin.token,
        body: { email: emails.otherSuper, name: "x", role: "MEMBER", response: await stepUpResponse(superAdmin) },
      });
      expect(again.status).toBe(409);
    });

    it("links can't be used for a disabled account", async () => {
      const { user } = await createUserWithToken({ email: `p01-disabled-${runSuffix}@example.com`, role: "MEMBER" });
      const token = await issueEnrollmentToken(user.id);
      await prisma.user.update({ where: { id: user.id }, data: { status: "DISABLED" } });
      expect((await enroll(token, new SoftAuthenticator())).status).toBe(400);
      expect(await passkeyCount(user.id)).toBe(0);
      await cleanupUsers([`p01-disabled-${runSuffix}@example.com`]);
    });

    it("open self-registration (when enabled) creates only a brand-new MEMBER account", async () => {
      process.env.ALLOW_OPEN_REGISTRATION = "true";
      const device = new SoftAuthenticator();
      const options = await apiRequest("/auth/register/options", { method: "POST", body: { email: emails.newcomer, name: "Newcomer" } });
      expect(options.status).toBe(200);
      // No account exists until the ceremony verifies.
      expect(await prisma.user.findUnique({ where: { email: emails.newcomer } })).toBeNull();

      const verify = await apiRequest("/auth/register/verify", {
        method: "POST",
        body: { email: emails.newcomer, response: device.createRegistrationResponse(options.data.challenge) },
      });
      expect(verify.status).toBe(200);
      const created = await prisma.user.findUniqueOrThrow({ where: { email: emails.newcomer } });
      expect(created.role).toBe("MEMBER");
      expect((await passkeyLogin(emails.newcomer, device)).status).toBe(200);
    });

    it("a registration response without user verification is rejected", async () => {
      process.env.ALLOW_OPEN_REGISTRATION = "true";
      const email = `p01-nouv-${runSuffix}@example.com`;
      const options = await apiRequest("/auth/register/options", { method: "POST", body: { email, name: "No UV" } });
      const verify = await apiRequest("/auth/register/verify", {
        method: "POST",
        body: { email, response: new SoftAuthenticator({ userVerified: false }).createRegistrationResponse(options.data.challenge) },
      });
      expect(verify.status).toBe(400);
      expect(await prisma.user.findUnique({ where: { email } })).toBeNull();
    });
  });
});
