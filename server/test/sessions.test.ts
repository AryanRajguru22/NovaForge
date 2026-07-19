import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { startTestServer, stopTestServer, apiRequest, createUserWithToken, cleanupUsers, runSuffix } from "./testServer.js";
import { prisma } from "../src/lib/prisma.js";
import { signAccessToken } from "../src/lib/jwt.js";

describe("session revocation is authoritative across devices", () => {
  const email = `session-revoke-${runSuffix}@example.com`;

  let laptopSessionId: string;
  let laptopToken: string;
  let phoneSessionId: string;
  let phoneToken: string;

  beforeAll(async () => {
    await startTestServer();
    await cleanupUsers([email]);

    const { user } = await createUserWithToken({ email, role: "MEMBER" });

    const laptop = await prisma.session.create({
      data: { userId: user.id, deviceId: "laptop-device", expiresAt: new Date(Date.now() + 3600_000) },
    });
    laptopSessionId = laptop.id;
    laptopToken = signAccessToken({ sub: user.id, sessionId: laptop.id });

    const phone = await prisma.session.create({
      data: { userId: user.id, deviceId: "phone-device", expiresAt: new Date(Date.now() + 3600_000) },
    });
    phoneSessionId = phone.id;
    phoneToken = signAccessToken({ sub: user.id, sessionId: phone.id });
  });

  afterAll(async () => {
    await cleanupUsers([email]);
    await stopTestServer();
  });

  it("both devices work before either is revoked", async () => {
    const laptopMe = await apiRequest("/auth/me", { token: laptopToken });
    expect(laptopMe.status).toBe(200);

    const phoneMe = await apiRequest("/auth/me", { token: phoneToken });
    expect(phoneMe.status).toBe(200);
  });

  it("revoking the phone's session from the laptop immediately rejects the phone's still-unexpired access token", async () => {
    const revoke = await apiRequest(`/auth/sessions/${phoneSessionId}`, { method: "DELETE", token: laptopToken });
    expect(revoke.status).toBe(200);

    // The phone's JWT is cryptographically untouched -- still signed correctly and
    // not expired -- but the Session row it points at is gone. Before this fix,
    // requireAuth only checked JWT validity, so this would have kept succeeding.
    const phoneMe = await apiRequest("/auth/me", { token: phoneToken });
    expect(phoneMe.status).toBe(401);

    const laptopMe = await apiRequest("/auth/me", { token: laptopToken });
    expect(laptopMe.status).toBe(200);
  });

  it("rejects requests for a session that never existed", async () => {
    const bogusToken = signAccessToken({ sub: "not-a-real-user", sessionId: "not-a-real-session" });
    const res = await apiRequest("/auth/me", { token: bogusToken });
    expect(res.status).toBe(401);
  });
});
