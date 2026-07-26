import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { authenticator } from "otplib";
import { startTestServer, stopTestServer, apiRequest, cleanupUsers, runSuffix } from "./testServer.js";
import { prisma } from "../src/lib/prisma.js";
import { hashSecret } from "../src/lib/hash.js";
import { encryptTotpSecret } from "../src/lib/totpSecretCrypto.js";
import { signAccessToken } from "../src/lib/jwt.js";

describe("user-controlled login-method preferences", () => {
  const email = `prefs-test-${runSuffix}@example.com`;
  const recoveryCode = "smoke-recovery-code-1";
  let userId: string;
  let token: string;
  let totpSecret: string;

  beforeAll(async () => {
    await startTestServer();
    await cleanupUsers([email]);

    const user = await prisma.user.create({ data: { email, name: "Prefs Test" } });
    userId = user.id;

    totpSecret = authenticator.generateSecret();
    await prisma.credential.create({
      data: { userId, type: "TOTP", secret: encryptTotpSecret(totpSecret), deviceLabel: "authenticator" },
    });
    await prisma.credential.create({
      data: { userId, type: "RECOVERY_CODE", secret: hashSecret(recoveryCode) },
    });

    const session = await prisma.session.create({
      data: { userId, deviceId: "prefs-test-device", expiresAt: new Date(Date.now() + 3600_000) },
    });
    token = signAccessToken({ sub: userId, sessionId: session.id });
  });

  afterAll(async () => {
    await cleanupUsers([email]);
    await stopTestServer();
  });

  it("allows TOTP login by default", async () => {
    const { status } = await apiRequest("/auth/login/totp", {
      method: "POST",
      body: { email, token: authenticator.generate(totpSecret) },
    });
    expect(status).toBe(200);
  });

  it("blocks TOTP login once disabled via preferences, and re-allows it once re-enabled", async () => {
    const disable = await apiRequest("/auth/preferences", {
      method: "PATCH",
      token,
      body: { totpLoginEnabled: false },
    });
    expect(disable.status).toBe(200);
    expect(disable.data.totpLoginEnabled).toBe(false);

    const blocked = await apiRequest("/auth/login/totp", {
      method: "POST",
      body: { email, token: authenticator.generate(totpSecret) },
    });
    expect(blocked.status).toBe(403);

    const reenable = await apiRequest("/auth/preferences", {
      method: "PATCH",
      token,
      body: { totpLoginEnabled: true },
    });
    expect(reenable.status).toBe(200);

    const allowed = await apiRequest("/auth/login/totp", {
      method: "POST",
      body: { email, token: authenticator.generate(totpSecret) },
    });
    expect(allowed.status).toBe(200);
  });

  it("leaves recovery-code login unaffected by the TOTP toggle", async () => {
    const { status } = await apiRequest("/auth/login/recovery-code", {
      method: "POST",
      body: { email, code: recoveryCode },
    });
    expect(status).toBe(200);
  });

  it("blocks recovery-code login once disabled via preferences", async () => {
    await prisma.credential.create({
      data: { userId, type: "RECOVERY_CODE", secret: hashSecret("second-recovery-code") },
    });

    const disable = await apiRequest("/auth/preferences", {
      method: "PATCH",
      token,
      body: { recoveryCodeLoginEnabled: false },
    });
    expect(disable.status).toBe(200);

    const blocked = await apiRequest("/auth/login/recovery-code", {
      method: "POST",
      body: { email, code: "second-recovery-code" },
    });
    expect(blocked.status).toBe(403);
  });

  it("records an audit entry for each preference change", async () => {
    const entries = await prisma.auditLog.findMany({
      where: { entityType: "User", entityId: userId, event: "auth_preference_changed" },
    });
    expect(entries.length).toBeGreaterThanOrEqual(3);
  });
});
