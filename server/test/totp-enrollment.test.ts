import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { authenticator } from "otplib";
import {
  startTestServer,
  stopTestServer,
  apiRequest,
  createUserWithToken,
  addMockPasskey,
  cleanupUsers,
  runSuffix,
} from "./testServer.js";
import { prisma } from "../src/lib/prisma.js";

// Regression coverage for a real gap: enrolling TOTP writes a brand-new,
// fully independent login path (same as minting recovery codes) and, on
// re-enrollment, deletes whatever TOTP credential the real user already had
// -- but it previously only required a valid session (requireAuth), not
// proof of holding the passkey. A stolen session cookie alone could hijack
// or plant a TOTP backdoor. /totp/verify now requires a fresh passkey
// signature immediately before the write, mirroring the recovery-codes
// options/generate step-up gate.
describe("TOTP enrollment requires a fresh passkey signature", () => {
  const email = `totp-enroll-${runSuffix}@example.com`;
  const noPasskeyEmail = `totp-enroll-nopasskey-${runSuffix}@example.com`;
  let token: string;
  let userId: string;

  beforeAll(async () => {
    await startTestServer();
    await cleanupUsers([email, noPasskeyEmail]);
    const created = await createUserWithToken({ email, role: "MEMBER" });
    token = created.token;
    userId = created.user.id;
    await addMockPasskey(userId);
  });

  afterAll(async () => {
    await cleanupUsers([email, noPasskeyEmail]);
    await stopTestServer();
  });

  it("rejects totp/verify/options for a user with no registered passkey", async () => {
    const { token: noPasskeyToken } = await createUserWithToken({ email: noPasskeyEmail, role: "MEMBER" });
    const res = await apiRequest("/auth/totp/verify/options", { method: "POST", token: noPasskeyToken });
    expect(res.status).toBe(400);
    expect(res.data.error).toMatch(/no passkeys/i);
  });

  it("rejects totp/verify without first requesting a passkey challenge", async () => {
    const setup = await apiRequest("/auth/totp/setup", { method: "POST", token });
    const code = authenticator.generate(setup.data.secret);

    const res = await apiRequest("/auth/totp/verify", {
      method: "POST",
      token,
      body: { token: code, response: { id: `mock-cred-${userId}` } },
    });
    expect(res.status).toBe(400);
    expect(res.data.error).toMatch(/passkey confirmation expired/i);
  });

  it("rejects enrollment against an unknown credential id", async () => {
    const setup = await apiRequest("/auth/totp/setup", { method: "POST", token });
    const code = authenticator.generate(setup.data.secret);
    await apiRequest("/auth/totp/verify/options", { method: "POST", token });

    const res = await apiRequest("/auth/totp/verify", {
      method: "POST",
      token,
      body: { token: code, response: { id: "not-a-real-credential" } },
    });
    expect(res.status).toBe(400);
    expect(res.data.error).toMatch(/unknown credential/i);
  });

  it("enrolls TOTP only after a valid passkey signature and correct code", async () => {
    const setup = await apiRequest("/auth/totp/setup", { method: "POST", token });
    const code = authenticator.generate(setup.data.secret);

    const options = await apiRequest("/auth/totp/verify/options", { method: "POST", token });
    expect(options.status).toBe(200);

    const res = await apiRequest("/auth/totp/verify", {
      method: "POST",
      token,
      body: { token: code, response: { id: `mock-cred-${userId}` } },
    });
    expect(res.status).toBe(200);
    expect(res.data.verified).toBe(true);

    const cred = await prisma.credential.findFirst({ where: { userId, type: "TOTP" } });
    expect(cred).not.toBeNull();
    // Encrypted at rest, not the plaintext secret returned by /totp/setup.
    expect(cred!.secret).toMatch(/^gcm1:/);
  });
});
