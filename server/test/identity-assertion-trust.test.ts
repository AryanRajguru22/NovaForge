import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  startTestServer,
  stopTestServer,
  apiRequest,
  createUserWithToken,
  cleanupUsers,
  runSuffix,
} from "./testServer.js";
import { prisma } from "../src/lib/prisma.js";
import { generateRefreshTokenId, signAccessToken } from "../src/lib/jwt.js";
import { configureIdentityKeyRing, generateSigningKey, getPublicJwks } from "../src/lib/identityKeys.js";
import { identityIssuer } from "../src/lib/identityAssertion.js";
import { createIdentityAssertionVerifier } from "../src/lib/identityAssertionVerifier.js";

// Session.trustLevel is only rewritten when the session checks in via
// /auth/session/refresh. An identity assertion issued between check-ins must
// carry the trust in effect at issue time (decayed), without that issuance
// itself mutating the session.
describe("identity assertions carry current effective trust", () => {
  const emailFor = (n: number) => `assert-trust-${n}-${runSuffix}@example.com`;
  const allEmails = Array.from({ length: 6 }, (_, i) => emailFor(i));
  const superEmail = `assert-trust-super-${runSuffix}@example.com`;
  let baseUrl: string;
  let service: { id: string; audience: string; token: string };
  let caseCounter = 0;

  beforeAll(async () => {
    baseUrl = await startTestServer();
    await cleanupUsers([...allEmails, superEmail]);
    configureIdentityKeyRing({ current: generateSigningKey("trust-key"), previous: [] });
    const superAdmin = await createUserWithToken({ email: superEmail, role: "SUPER_ADMIN" });
    const name = `relying-trust-${runSuffix}`;
    const account = await apiRequest("/service-accounts", {
      method: "POST",
      token: superAdmin.token,
      body: { name, audience: name, scopes: ["identity:assert"] },
    });
    expect(account.status).toBe(201);
    const credential = await apiRequest(`/service-accounts/${account.data.id}/credentials`, {
      method: "POST",
      token: superAdmin.token,
      body: {},
    });
    expect(credential.status).toBe(201);
    service = { id: account.data.id, audience: account.data.audience, token: credential.data.token };
  });

  afterAll(async () => {
    configureIdentityKeyRing(null);
    await prisma.serviceCredential.deleteMany({ where: { serviceAccountId: service?.id } });
    await prisma.serviceAccount.deleteMany({ where: { id: service?.id } });
    await cleanupUsers([...allEmails, superEmail]);
    await stopTestServer();
  });

  async function sessionVerifiedHoursAgo(hoursAgo: number, trustLevel = 100) {
    const user = await prisma.user.create({ data: { email: emailFor(caseCounter++), name: "Trust", role: "APPROVER" } });
    const session = await prisma.session.create({
      data: {
        userId: user.id,
        deviceId: "test-device",
        trustLevel,
        lastVerifiedAt: new Date(Date.now() - hoursAgo * 3_600_000),
        expiresAt: new Date(Date.now() + 24 * 3_600_000),
        currentRefreshTokenId: generateRefreshTokenId(),
      },
    });
    return { user, session, accessToken: signAccessToken({ sub: user.id, sessionId: session.id }) };
  }

  async function assertTrust(accessToken: string): Promise<number> {
    const res = await fetch(`${baseUrl}/api/internal/identity-assertions`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${service.token}` },
      body: JSON.stringify({ accessToken }),
    });
    expect(res.status).toBe(200);
    const { assertion } = await res.json();
    const verify = createIdentityAssertionVerifier({ issuer: identityIssuer(), audience: service.audience, jwks: getPublicJwks() });
    return verify(assertion).trust_level;
  }

  async function expectSessionUnchanged(session: { id: string; trustLevel: number; lastVerifiedAt: Date; currentRefreshTokenId: string | null }) {
    const row = await prisma.session.findUniqueOrThrow({ where: { id: session.id } });
    expect(row.trustLevel).toBe(session.trustLevel);
    expect(row.lastVerifiedAt.getTime()).toBe(session.lastVerifiedAt.getTime());
    expect(row.currentRefreshTokenId).toBe(session.currentRefreshTokenId);
  }

  it("an old session whose stored trust was never refreshed is asserted at its decayed value", async () => {
    const { session, accessToken } = await sessionVerifiedHoursAgo(10); // 10h * 5/h = 50 points
    expect(session.trustLevel).toBe(100);
    expect(await assertTrust(accessToken)).toBe(50);
    await expectSessionUnchanged(session);
  });

  it("applies decay to a partially-decayed stored value, and never below zero", async () => {
    const partial = await sessionVerifiedHoursAgo(2, 80); // 80 - 10
    expect(await assertTrust(partial.accessToken)).toBe(70);
    await expectSessionUnchanged(partial.session);

    const exhausted = await sessionVerifiedHoursAgo(40, 100); // 100 - 200, clamped
    expect(await assertTrust(exhausted.accessToken)).toBe(0);
    await expectSessionUnchanged(exhausted.session);
  });

  it("a freshly verified session is asserted at its stored trust, unchanged", async () => {
    const { session, accessToken } = await sessionVerifiedHoursAgo(0);
    expect(await assertTrust(accessToken)).toBe(100);
    await expectSessionUnchanged(session);
  });

  it("repeated assertions do not ratchet or reset trust", async () => {
    const { session, accessToken } = await sessionVerifiedHoursAgo(6); // 70
    expect(await assertTrust(accessToken)).toBe(70);
    expect(await assertTrust(accessToken)).toBe(70);
    await expectSessionUnchanged(session);
  });
});
