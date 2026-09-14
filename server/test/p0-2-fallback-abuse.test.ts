import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { authenticator } from "otplib";
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
import { prisma } from "../src/lib/prisma.js";
import { hashSecret } from "../src/lib/hash.js";
import { encryptTotpSecret } from "../src/lib/totpSecretCrypto.js";
import { canonicalRecoveryCode } from "../src/routes/auth.js";
import { BASE_LOCK_MS, MAX_ATTEMPTS, fallbackSubject, reserveAuthAttempt } from "../src/lib/authThrottle.js";
import { resetRateLimitBuckets } from "../src/middleware/rateLimit.js";

// P0-2: TOTP / recovery-code abuse.

function wrongCodeFor(secret: string): string {
  const valid = authenticator.generate(secret);
  return String((Number(valid) + 500_000) % 1_000_000).padStart(6, "0");
}

describe("P0-2: fallback-factor guessing, replay and normalization", () => {
  const created: string[] = [];

  async function makeUser(label: string) {
    const email = `p02-${label}-${runSuffix}@example.com`;
    created.push(email);
    const { user, token } = await createUserWithToken({ email, role: "MEMBER" });
    const secret = authenticator.generateSecret();
    await prisma.credential.create({ data: { userId: user.id, type: "TOTP", secret: encryptTotpSecret(secret) } });
    return { user, token, email, secret };
  }

  const totpLogin = (email: string, token: string) => apiRequest("/auth/login/totp", { method: "POST", body: { email, token } });
  const recoveryLogin = (email: string, code: string) => apiRequest("/auth/login/recovery-code", { method: "POST", body: { email, code } });
  const throttleRow = (email: string) => prisma.authThrottle.findUnique({ where: { subject: fallbackSubject(email) } });

  beforeAll(async () => {
    await startTestServer();
  });

  beforeEach(() => {
    // Isolate the persistent (database) throttle from the in-memory burst
    // limiter unless a test is specifically about the latter.
    resetRateLimitBuckets();
  });

  afterAll(async () => {
    await prisma.authThrottle.deleteMany({ where: { subject: { in: created.map(fallbackSubject) } } });
    await cleanupUsers(created);
    await stopTestServer();
  });

  describe("identity canonicalization", () => {
    it("case and whitespace variants of one email share the in-memory burst limiter bucket", async () => {
      const { email, secret } = await makeUser("burst");
      const variants = [email, email.toUpperCase(), `  ${email}  `, email.replace(/^p/, "P"), ` ${email.toUpperCase()}`];
      for (const variant of variants) {
        const res = await totpLogin(variant, wrongCodeFor(secret));
        expect(res.status).toBe(400);
      }
      // Clear the persistent budget so only the in-memory limiter can refuse
      // the next attempt -- proving the variants shared its bucket.
      await prisma.authThrottle.deleteMany({ where: { subject: fallbackSubject(email) } });
      // A 6th attempt under yet another spelling is refused before any code check.
      const blocked = await totpLogin(`\t${email.toUpperCase()}\n`, authenticator.generate(secret));
      expect(blocked.status).toBe(429);
    });

    it("case and whitespace variants of one email share the persistent per-account budget", async () => {
      const { email, secret } = await makeUser("persistent");
      const variants = [email, email.toUpperCase(), `  ${email}`, `${email.toUpperCase()}  `, email];
      for (const variant of variants) {
        resetRateLimitBuckets(); // defeat the in-memory limiter entirely, as a distributed attacker would
        expect((await totpLogin(variant, wrongCodeFor(secret))).status).toBe(400);
      }
      resetRateLimitBuckets();
      const blocked = await totpLogin(`  ${email.toUpperCase()}  `, authenticator.generate(secret));
      expect(blocked.status).toBe(429);
      expect(blocked.data.error).toMatch(/Too many attempts for this account/);
      expect(await prisma.authThrottle.count({ where: { subject: { contains: email } } })).toBe(1);
      expect((await throttleRow(email))?.lockedUntil).not.toBeNull();
    });
  });

  describe("TOTP", () => {
    it("bounds excessive attempts: after the budget, even the correct code is refused until the lock expires", async () => {
      const { email, secret, user } = await makeUser("excessive");
      for (let i = 0; i < MAX_ATTEMPTS; i++) {
        resetRateLimitBuckets();
        expect((await totpLogin(email, wrongCodeFor(secret))).status).toBe(400);
      }
      resetRateLimitBuckets();
      const locked = await totpLogin(email, authenticator.generate(secret));
      expect(locked.status).toBe(429);
      expect((await throttleRow(email))!.lockedUntil!.getTime()).toBeGreaterThan(Date.now() + BASE_LOCK_MS - 60_000);
      expect(await prisma.session.count({ where: { userId: user.id, deviceId: { not: "test-device" } } })).toBe(0);

      const lockEvent = await prisma.auditLog.findFirst({ where: { event: "AUTH_FALLBACK_LOCKED" }, orderBy: { seq: "desc" } });
      expect(lockEvent).not.toBeNull();
      const failures = await prisma.auditLog.count({ where: { entityId: user.id, event: "LOGIN_FAILED_TOTP" } });
      expect(failures).toBe(MAX_ATTEMPTS);
    });

    it("the persistent budget holds under genuinely concurrent guesses", async () => {
      const subject = fallbackSubject(`p02-concurrent-${runSuffix}@example.com`);
      created.push(`p02-concurrent-${runSuffix}@example.com`);
      const decisions = await Promise.all(Array.from({ length: 20 }, () => reserveAuthAttempt(subject)));
      expect(decisions.filter((d) => d.allowed)).toHaveLength(MAX_ATTEMPTS);
    });

    it("lock duration escalates for repeated lockouts", async () => {
      const email = `p02-escalate-${runSuffix}@example.com`;
      created.push(email);
      const subject = fallbackSubject(email);
      const t0 = new Date();
      for (let i = 0; i < MAX_ATTEMPTS; i++) expect((await reserveAuthAttempt(subject, t0)).allowed).toBe(true);
      const first = await reserveAuthAttempt(subject, t0);
      expect(first).toEqual({ allowed: false, retryAfterMs: BASE_LOCK_MS });

      const t1 = new Date(t0.getTime() + BASE_LOCK_MS + 1);
      for (let i = 0; i < MAX_ATTEMPTS; i++) expect((await reserveAuthAttempt(subject, t1)).allowed).toBe(true);
      const second = await reserveAuthAttempt(subject, t1);
      expect(second).toEqual({ allowed: false, retryAfterMs: BASE_LOCK_MS * 2 });
    });

    it("a successful TOTP login works once the lock has expired, and resets the budget", async () => {
      const { email, secret } = await makeUser("retry");
      for (let i = 0; i < MAX_ATTEMPTS; i++) {
        resetRateLimitBuckets();
        await totpLogin(email, wrongCodeFor(secret));
      }
      resetRateLimitBuckets();
      expect((await totpLogin(email, authenticator.generate(secret))).status).toBe(429);

      // Lock period elapses.
      await prisma.authThrottle.update({ where: { subject: fallbackSubject(email) }, data: { lockedUntil: new Date(Date.now() - 1000) } });
      resetRateLimitBuckets();
      const ok = await totpLogin(email, authenticator.generate(secret));
      expect(ok.status).toBe(200);
      const row = await throttleRow(email);
      expect(row).toMatchObject({ attempts: 0, lockLevel: 0, lockedUntil: null });
    });

    it("rejects a repeated TOTP code within its validity window", async () => {
      const { email, secret, user } = await makeUser("replay");
      const code = authenticator.generate(secret);
      expect((await totpLogin(email, code)).status).toBe(200);
      const replay = await totpLogin(email, code);
      expect(replay.status).toBe(400);
      expect(replay.data.error).toMatch(/already been used/);
      expect(await prisma.auditLog.count({ where: { entityId: user.id, event: "LOGIN_FAILED_TOTP" } })).toBe(1);
    });

    it("of two concurrent logins with the same code, exactly one succeeds", async () => {
      const { email, secret } = await makeUser("replay-race");
      const code = authenticator.generate(secret);
      const results = await Promise.all([totpLogin(email, code), totpLogin(email, code)]);
      expect(results.map((r) => r.status).sort()).toEqual([200, 400]);
    });

    it("the code used to confirm enrollment can't be replayed to sign in", async () => {
      const email = `p02-enroll-${runSuffix}@example.com`;
      created.push(email);
      const { user, token } = await createUserWithToken({ email, role: "MEMBER" });
      await addMockPasskey(user.id);
      const setup = await apiRequest("/auth/totp/setup", { method: "POST", token });
      const code = authenticator.generate(setup.data.secret);
      const options = await apiRequest("/auth/totp/verify/options", { method: "POST", token });
      const enrolled = await apiRequest("/auth/totp/verify", {
        method: "POST",
        token,
        body: { token: code, response: authenticatorFor(user.id).createAssertion(options.data.challenge) },
      });
      expect(enrolled.status).toBe(200);
      expect((await totpLogin(email, code)).status).toBe(400);
    });

    it("unknown accounts get the same generic failure and the same throttling", async () => {
      const email = `p02-ghost-${runSuffix}@example.com`;
      created.push(email);
      const res = await totpLogin(email, "123456");
      expect(res.status).toBe(400);
      expect(res.data.error).toBe("Invalid email or code");
      expect(await throttleRow(email)).not.toBeNull();
    });
  });

  describe("recovery codes", () => {
    it("guessing is bounded: after the budget the correct code is refused and NOT consumed", async () => {
      const { email, user } = await makeUser("rc-guess");
      const realCode = "ABCD-EFGH-JKMN-PQRS";
      await prisma.credential.create({ data: { userId: user.id, type: "RECOVERY_CODE", secret: hashSecret(canonicalRecoveryCode(realCode)) } });

      for (let i = 0; i < MAX_ATTEMPTS; i++) {
        resetRateLimitBuckets();
        expect((await recoveryLogin(email, `ZZZZ-ZZZZ-ZZZZ-ZZ${String(i).padStart(2, "0")}`)).status).toBe(400);
      }
      resetRateLimitBuckets();
      expect((await recoveryLogin(email, realCode)).status).toBe(429);
      expect(await prisma.credential.count({ where: { userId: user.id, type: "RECOVERY_CODE" } })).toBe(1);
    });

    it("a legitimate code works once, in any case/separator form, and is then consumed", async () => {
      const { email, user } = await makeUser("rc-legit");
      const realCode = "7K3M-Q9TX-2HWP-8RVB";
      await prisma.credential.create({ data: { userId: user.id, type: "RECOVERY_CODE", secret: hashSecret(canonicalRecoveryCode(realCode)) } });

      expect((await recoveryLogin(email, " 7k3mq9tx 2hwp8rvb ")).status).toBe(200);
      expect(await prisma.credential.count({ where: { userId: user.id, type: "RECOVERY_CODE" } })).toBe(0);
      expect((await recoveryLogin(email, realCode)).status).toBe(400);
    });

    it("codes issued before the format change still redeem exactly as displayed", async () => {
      const { email, user } = await makeUser("rc-legacy");
      await prisma.credential.create({ data: { userId: user.id, type: "RECOVERY_CODE", secret: hashSecret("1234-5678") } });
      expect((await recoveryLogin(email, "1234-5678")).status).toBe(200);
    });

    it("of two concurrent redemptions of one code, exactly one succeeds", async () => {
      const { email, user } = await makeUser("rc-race");
      const realCode = "M4X8-T2QZ-9PKV-HR3W";
      await prisma.credential.create({ data: { userId: user.id, type: "RECOVERY_CODE", secret: hashSecret(canonicalRecoveryCode(realCode)) } });
      const results = await Promise.all([recoveryLogin(email, realCode), recoveryLogin(email, realCode)]);
      expect(results.map((r) => r.status).sort()).toEqual([200, 400]);
    });

    it("newly generated codes carry 80 bits of entropy and are stored only as hashes", async () => {
      const { user, token } = await makeUser("rc-generate");
      await addMockPasskey(user.id);
      const options = await apiRequest("/auth/recovery-codes/options", { method: "POST", token });
      const res = await apiRequest("/auth/recovery-codes/generate", {
        method: "POST",
        token,
        body: { response: authenticatorFor(user.id).createAssertion(options.data.challenge) },
      });
      expect(res.status).toBe(200);
      const codes = res.data.codes as string[];
      expect(codes).toHaveLength(10);
      for (const code of codes) expect(code).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}$/);
      const stored = await prisma.credential.findMany({ where: { userId: user.id, type: "RECOVERY_CODE" } });
      for (const row of stored) for (const code of codes) expect(row.secret).not.toContain(canonicalRecoveryCode(code));
    });
  });

  describe("no easy denial of service", () => {
    it("locking an account's fallback factors never blocks its passkey sign-in", async () => {
      const { email, secret, user } = await makeUser("dos");
      await addMockPasskey(user.id);
      for (let i = 0; i <= MAX_ATTEMPTS; i++) {
        resetRateLimitBuckets();
        await totpLogin(email, wrongCodeFor(secret));
      }
      expect((await throttleRow(email))?.lockedUntil?.getTime()).toBeGreaterThan(Date.now());

      resetRateLimitBuckets();
      const options = await apiRequest("/auth/login/options", { method: "POST", body: { email } });
      const login = await apiRequest("/auth/login/verify", {
        method: "POST",
        body: { email, response: authenticatorFor(user.id).createAssertion(options.data.challenge) },
      });
      expect(login.status).toBe(200);
    });
  });
});
