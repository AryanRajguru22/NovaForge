import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import jwt from "jsonwebtoken";
import { authenticator } from "otplib";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import {
  startTestServer,
  stopTestServer,
  apiRequest,
  createUserWithToken,
  addMockPasskey,
  authenticatorFor,
  governanceProof,
  cleanupUsers,
  runSuffix,
} from "./testServer.js";
import { prisma } from "../src/lib/prisma.js";
import { env } from "../src/lib/env.js";
import { generateRefreshTokenId, signAccessToken, signRefreshToken } from "../src/lib/jwt.js";
import { encryptTotpSecret } from "../src/lib/totpSecretCrypto.js";
import {
  configureIdentityKeyRing,
  generateSigningKey,
  getPublicJwks,
  IdentityKeysUnavailableError,
  toPublicJwk,
  type SigningKey,
} from "../src/lib/identityKeys.js";
import { identityIssuer } from "../src/lib/identityAssertion.js";
import { createIdentityAssertionVerifier, IDENTITY_ASSERTION_TYP } from "../src/lib/identityAssertionVerifier.js";

// P0-6: account status, service identities, and identity assertions a
// downstream service can verify but never forge.

describe("P0-6: account status and service trust", () => {
  const emails = {
    superAdmin: `p06-super-${runSuffix}@example.com`,
    otherSuper: `p06-super2-${runSuffix}@example.com`,
    admin: `p06-admin-${runSuffix}@example.com`,
    worker: `p06-worker-${runSuffix}@example.com`,
    authority: `p06-authority-${runSuffix}@example.com`,
  };
  let baseUrl: string;
  let superAdmin: { id: string; token: string };
  let admin: { id: string; token: string };
  const serviceIds: string[] = [];
  let keyA: SigningKey;

  beforeAll(async () => {
    baseUrl = await startTestServer();
    keyA = generateSigningKey("key-a");
    configureIdentityKeyRing({ current: keyA, previous: [] });
    const s = await createUserWithToken({ email: emails.superAdmin, role: "SUPER_ADMIN" });
    superAdmin = { id: s.user.id, token: s.token };
    await addMockPasskey(superAdmin.id);
    await createUserWithToken({ email: emails.otherSuper, role: "SUPER_ADMIN" });
    const a = await createUserWithToken({ email: emails.admin, role: "ADMIN" });
    admin = { id: a.user.id, token: a.token };
  });

  afterEach(() => {
    configureIdentityKeyRing({ current: keyA, previous: [] });
  });

  afterAll(async () => {
    configureIdentityKeyRing(null);
    await prisma.serviceCredential.deleteMany({ where: { serviceAccountId: { in: serviceIds } } });
    await prisma.serviceAccount.deleteMany({ where: { id: { in: serviceIds } } });
    await cleanupUsers(Object.values(emails));
    await stopTestServer();
  });

  /** A fresh user with a real session (current refresh jti on record), a passkey and TOTP. */
  async function makeUser(email: string, role: "MEMBER" | "APPROVER" = "MEMBER") {
    await cleanupUsers([email]);
    const existing = await prisma.user.findUnique({ where: { email } });
    const user = existing ?? (await prisma.user.create({ data: { email, name: "P0-6", role } }));
    await prisma.user.update({ where: { id: user.id }, data: { status: "ACTIVE", role } });
    const jti = generateRefreshTokenId();
    const session = await prisma.session.create({
      data: { userId: user.id, deviceId: "test-device", expiresAt: new Date(Date.now() + 3_600_000), currentRefreshTokenId: jti },
    });
    await addMockPasskey(user.id);
    const totpSecret = authenticator.generateSecret();
    await prisma.credential.create({ data: { userId: user.id, type: "TOTP", secret: encryptTotpSecret(totpSecret) } });
    return {
      user,
      session,
      totpSecret,
      accessToken: signAccessToken({ sub: user.id, sessionId: session.id }),
      refreshToken: signRefreshToken({ sub: user.id, sessionId: session.id }, jti),
    };
  }

  async function createService(name: string, scopes: string[] = ["identity:assert", "identity:introspect"]) {
    const account = await apiRequest("/service-accounts", {
      method: "POST",
      token: superAdmin.token,
      body: { name: `${name}-${runSuffix}`, audience: `${name}-${runSuffix}`, scopes },
    });
    expect(account.status).toBe(201);
    serviceIds.push(account.data.id);
    const credential = await apiRequest(`/service-accounts/${account.data.id}/credentials`, { method: "POST", token: superAdmin.token, body: {} });
    expect(credential.status).toBe(201);
    return { id: account.data.id as string, audience: account.data.audience as string, token: credential.data.token as string, credentialId: credential.data.credentialId as string };
  }

  async function serviceCall(path: string, serviceToken: string, body: object) {
    const res = await fetch(`${baseUrl}/api${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${serviceToken}` },
      body: JSON.stringify(body),
    });
    return { status: res.status, data: await res.json().catch(() => undefined) };
  }

  async function downstreamVerifier(audience: string) {
    // Exactly what a relying service has: the issuer name and the PUBLIC JWKS.
    const jwks = await (await fetch(`${baseUrl}/.well-known/jwks.json`)).json();
    for (const key of jwks.keys) expect(key).not.toHaveProperty("d");
    return createIdentityAssertionVerifier({ issuer: identityIssuer(), audience, jwks });
  }

  describe("account status", () => {
    it("disabling a user revokes their existing session and refresh credential, and blocks every sign-in path", async () => {
      const u = await makeUser(emails.worker);
      expect((await apiRequest("/auth/me", { token: u.accessToken })).status).toBe(200);

      const disable = await apiRequest(`/users/${u.user.id}/status`, {
        method: "PATCH",
        token: superAdmin.token,
        body: { status: "DISABLED", reason: "left the organization", response: await governanceProof(superAdmin, "user") },
      });
      expect(disable.status).toBe(200);
      expect(await prisma.session.count({ where: { userId: u.user.id } })).toBe(0);

      expect((await apiRequest("/auth/me", { token: u.accessToken })).status).toBe(401);
      expect((await apiRequest("/auth/session/refresh", { method: "POST", refreshToken: u.refreshToken })).status).toBe(401);

      // Passkey login: the credential is valid, but the account isn't.
      const options = await apiRequest("/auth/login/options", { method: "POST", body: { email: emails.worker } });
      const passkey = await apiRequest("/auth/login/verify", {
        method: "POST",
        body: { email: emails.worker, response: authenticatorFor(u.user.id).createAssertion(options.data.challenge) },
      });
      expect(passkey.status).toBe(403);

      const totp = await apiRequest("/auth/login/totp", { method: "POST", body: { email: emails.worker, token: authenticator.generate(u.totpSecret) } });
      expect(totp.status).toBe(403);
      expect(await prisma.session.count({ where: { userId: u.user.id } })).toBe(0);

      const audit = await prisma.auditLog.findFirst({ where: { entityId: u.user.id, event: "ACCOUNT_STATUS_CHANGED" } });
      expect(audit?.metadata).toMatchObject({ from: "ACTIVE", to: "DISABLED", sessionsRevoked: 1 });
    });

    it("a non-ACTIVE status is authoritative on its own: a surviving session and refresh token are rejected", async () => {
      const u = await makeUser(emails.authority, "APPROVER");
      // Status flipped without the route's session cleanup.
      await prisma.user.update({ where: { id: u.user.id }, data: { status: "SUSPENDED" } });
      expect(await prisma.session.count({ where: { userId: u.user.id } })).toBe(1);

      expect((await apiRequest("/auth/me", { token: u.accessToken })).status).toBe(401);
      const refresh = await apiRequest("/auth/session/refresh", { method: "POST", refreshToken: u.refreshToken });
      expect(refresh.status).toBe(401);
      const session = await prisma.session.findUniqueOrThrow({ where: { id: u.session.id } });
      expect(session.previousRefreshTokenId).toBeNull(); // never rotated
    });

    it("a disabled user can't perform privileged actions even as SUPER_ADMIN", async () => {
      const email = `p06-disabled-super-${runSuffix}@example.com`;
      const { user, token } = await createUserWithToken({ email, role: "SUPER_ADMIN" });
      await prisma.user.update({ where: { id: user.id }, data: { status: "DISABLED" } });
      expect((await apiRequest("/users", { token })).status).toBe(401);
      expect((await apiRequest(`/users/${admin.id}/role`, { method: "PATCH", token, body: { role: "SUPER_ADMIN" } })).status).toBe(401);
      await cleanupUsers([email]);
    });

    it("reactivation restores sign-in", async () => {
      const u = await makeUser(emails.worker);
      await prisma.user.update({ where: { id: u.user.id }, data: { status: "DISABLED" } });
      const enable = await apiRequest(`/users/${u.user.id}/status`, {
        method: "PATCH",
        token: superAdmin.token,
        body: { status: "ACTIVE", response: await governanceProof(superAdmin, "user") },
      });
      expect(enable.status).toBe(200);
      const options = await apiRequest("/auth/login/options", { method: "POST", body: { email: emails.worker } });
      const login = await apiRequest("/auth/login/verify", {
        method: "POST",
        body: { email: emails.worker, response: authenticatorFor(u.user.id).createAssertion(options.data.challenge) },
      });
      expect(login.status).toBe(200);
    });

    it("status changes are restricted: not by ADMIN, and never on yourself", async () => {
      // (The "last active super admin" guard in the route is defense-in-depth:
      // the acting super admin is itself active and can't target itself, so
      // that state isn't reachable through this endpoint.)
      const u = await makeUser(emails.worker);
      expect((await apiRequest(`/users/${u.user.id}/status`, { method: "PATCH", token: admin.token, body: { status: "DISABLED" } })).status).toBe(403);
      expect(
        (
          await apiRequest(`/users/${superAdmin.id}/status`, {
            method: "PATCH",
            token: superAdmin.token,
            body: { status: "DISABLED", response: await governanceProof(superAdmin, "user") },
          })
        ).status,
      ).toBe(400);
      expect((await prisma.user.findUniqueOrThrow({ where: { id: superAdmin.id } })).status).toBe("ACTIVE");
    });
  });

  describe("service identity and identity assertions", () => {
    it("a service exchanges a live user session for an assertion that a downstream verifier accepts", async () => {
      const service = await createService("relying-a");
      const u = await makeUser(emails.authority, "APPROVER");
      const res = await serviceCall("/internal/identity-assertions", service.token, { accessToken: u.accessToken });
      expect(res.status).toBe(200);

      const verify = await downstreamVerifier(service.audience);
      const claims = verify(res.data.assertion);
      expect(claims).toMatchObject({
        iss: identityIssuer(),
        aud: service.audience,
        sub: u.user.id,
        sid: u.session.id,
        role: "APPROVER",
        account_status: "ACTIVE",
        principal_type: "user",
        token_use: "identity_assertion",
      });
      expect(claims.exp - claims.iat).toBeLessThanOrEqual(300);
      const header = jwt.decode(res.data.assertion, { complete: true })!.header;
      expect(header).toMatchObject({ alg: "ES256", kid: "key-a", typ: IDENTITY_ASSERTION_TYP });

      const introspect = await serviceCall("/internal/introspect", service.token, { assertion: res.data.assertion });
      expect(introspect.data).toMatchObject({ active: true, sub: u.user.id, role: "APPROVER" });
    });

    it("introspection reports inactive once the session is revoked or the user disabled", async () => {
      const service = await createService("relying-b");
      const u = await makeUser(emails.authority, "APPROVER");
      const { data } = await serviceCall("/internal/identity-assertions", service.token, { accessToken: u.accessToken });
      await apiRequest("/auth/logout", { method: "POST", token: u.accessToken });
      expect((await serviceCall("/internal/introspect", service.token, { assertion: data.assertion })).data).toEqual({ active: false });

      const u2 = await makeUser(emails.authority, "APPROVER");
      const second = await serviceCall("/internal/identity-assertions", service.token, { accessToken: u2.accessToken });
      await prisma.user.update({ where: { id: u2.user.id }, data: { status: "DISABLED" } });
      expect((await serviceCall("/internal/introspect", service.token, { assertion: second.data.assertion })).data).toEqual({ active: false });
      // ...and no new assertion can be obtained for a disabled user.
      expect((await serviceCall("/internal/identity-assertions", service.token, { accessToken: u2.accessToken })).status).toBe(401);
    });

    it("the audience is the authenticated service's own; one service's assertion is useless to another", async () => {
      const a = await createService("relying-c");
      const b = await createService("relying-d");
      const u = await makeUser(emails.authority, "APPROVER");
      const { data } = await serviceCall("/internal/identity-assertions", a.token, { accessToken: u.accessToken, audience: b.audience });
      expect(jwt.decode(data.assertion)).toMatchObject({ aud: a.audience });
      expect(() => downstreamVerifierSync(b.audience)(data.assertion)).toThrow();
      expect((await serviceCall("/internal/introspect", b.token, { assertion: data.assertion })).data).toEqual({ active: false });
    });

    function downstreamVerifierSync(audience: string) {
      return createIdentityAssertionVerifier({ issuer: identityIssuer(), audience, jwks: getPublicJwks() });
    }

    describe("a downstream verifier cannot be fooled into accepting a forged identity", () => {
      const audience = "downstream-under-test";
      const baseClaims = () => ({
        token_use: "identity_assertion",
        principal_type: "user",
        sid: randomUUID(),
        role: "SUPER_ADMIN",
        account_status: "ACTIVE",
        auth_time: Math.floor(Date.now() / 1000),
        trust_level: 100,
      });
      const sign = (key: SigningKey, claims: object, opts: jwt.SignOptions = {}) => {
        const options: jwt.SignOptions = {
          algorithm: "ES256",
          keyid: key.kid,
          header: { alg: "ES256", typ: IDENTITY_ASSERTION_TYP, kid: key.kid },
          issuer: identityIssuer(),
          audience,
          subject: "AUTHORITY-017",
          jwtid: randomUUID(),
          expiresIn: 300,
          ...opts,
        };
        if ("exp" in claims) delete options.expiresIn;
        return jwt.sign(claims, key.privateKey, options);
      };

      it("accepts a genuine assertion (control)", () => {
        expect(downstreamVerifierSync(audience)(sign(keyA, baseClaims())).sub).toBe("AUTHORITY-017");
      });

      it("rejects an assertion signed by an attacker's own ES256 key, even reusing the trusted kid", () => {
        const attackerKey = { ...generateSigningKey("key-a") };
        expect(() => downstreamVerifierSync(audience)(sign(attackerKey, baseClaims()))).toThrow();
      });

      it("rejects alg=none", () => {
        const header = Buffer.from(JSON.stringify({ alg: "none", typ: IDENTITY_ASSERTION_TYP, kid: "key-a" })).toString("base64url");
        const now = Math.floor(Date.now() / 1000);
        const payload = Buffer.from(
          JSON.stringify({ ...baseClaims(), iss: identityIssuer(), aud: audience, sub: "AUTHORITY-017", jti: "x", iat: now, exp: now + 60 }),
        ).toString("base64url");
        expect(() => downstreamVerifierSync(audience)(`${header}.${payload}.`)).toThrow();
      });

      it("rejects HS256 key confusion (public key material used as an HMAC secret)", () => {
        const publicJwk = JSON.stringify(toPublicJwk(keyA));
        const publicPem = keyA.publicKey.export({ type: "spki", format: "pem" }).toString();
        for (const secret of [publicJwk, publicPem]) {
          const forged = jwt.sign({ ...baseClaims(), sub: "AUTHORITY-017" }, secret, {
            algorithm: "HS256",
            header: { alg: "HS256", typ: IDENTITY_ASSERTION_TYP, kid: "key-a" },
            issuer: identityIssuer(),
            audience,
            jwtid: randomUUID(),
            expiresIn: 300,
          });
          expect(() => downstreamVerifierSync(audience)(forged)).toThrow();
        }
      });

      it("rejects a NovaForge session token (HS256, session audience) presented as an assertion", () => {
        const sessionToken = signAccessToken({ sub: superAdmin.id, sessionId: randomUUID() });
        expect(() => downstreamVerifierSync(audience)(sessionToken)).toThrow();
      });

      it("rejects a wrong issuer", () => {
        expect(() => downstreamVerifierSync(audience)(sign(keyA, baseClaims(), { issuer: "https://evil.example" }))).toThrow(/issuer/);
      });

      it("rejects a wrong audience", () => {
        expect(() => downstreamVerifierSync(audience)(sign(keyA, baseClaims(), { audience: "some-other-service" }))).toThrow(/audience/);
      });

      it("rejects an expired assertion", () => {
        const past = Math.floor(Date.now() / 1000) - 3600;
        const expired = sign(keyA, { ...baseClaims(), iat: past, exp: past + 300 });
        expect(() => downstreamVerifierSync(audience)(expired)).toThrow(/expired/);
      });

      it("rejects an assertion with an excessive lifetime", () => {
        expect(() => downstreamVerifierSync(audience)(sign(keyA, baseClaims(), { expiresIn: 86_400 }))).toThrow(/lifetime/);
      });

      it("rejects a wrong token type and a non-ACTIVE principal", () => {
        expect(() => downstreamVerifierSync(audience)(sign(keyA, { ...baseClaims(), token_use: "access" }))).toThrow();
        expect(() => downstreamVerifierSync(audience)(sign(keyA, { ...baseClaims(), account_status: "DISABLED" }))).toThrow();
      });
    });

    it("handles signing-key rotation: old assertions verify while the old public key is published, then stop", async () => {
      const service = await createService("relying-rotation");
      const u = await makeUser(emails.authority, "APPROVER");
      const oldAssertion = (await serviceCall("/internal/identity-assertions", service.token, { accessToken: u.accessToken })).data.assertion;

      const keyB = generateSigningKey("key-b");
      configureIdentityKeyRing({ current: keyB, previous: [{ kid: keyA.kid, publicKey: keyA.publicKey }] });
      const jwks = await (await fetch(`${baseUrl}/.well-known/jwks.json`)).json();
      expect(jwks.keys.map((k: { kid: string }) => k.kid).sort()).toEqual(["key-a", "key-b"]);

      const newAssertion = (await serviceCall("/internal/identity-assertions", service.token, { accessToken: u.accessToken })).data.assertion;
      expect(jwt.decode(newAssertion, { complete: true })!.header.kid).toBe("key-b");
      const verifier = await downstreamVerifier(service.audience);
      expect(verifier(oldAssertion).sub).toBe(u.user.id);
      expect(verifier(newAssertion).sub).toBe(u.user.id);

      configureIdentityKeyRing({ current: keyB, previous: [] });
      const afterRetirement = await downstreamVerifier(service.audience);
      expect(() => afterRetirement(oldAssertion)).toThrow(/Unknown signing key/);
      expect(afterRetirement(newAssertion).sub).toBe(u.user.id);
    });

    it("refuses to issue assertions in production without a configured signing key", () => {
      configureIdentityKeyRing(null);
      const previousEnv = process.env.NODE_ENV;
      const previousKey = process.env.IDENTITY_SIGNING_PRIVATE_KEY;
      delete process.env.IDENTITY_SIGNING_PRIVATE_KEY;
      process.env.NODE_ENV = "production";
      try {
        expect(() => getPublicJwks()).toThrow(IdentityKeysUnavailableError);
      } finally {
        process.env.NODE_ENV = previousEnv;
        if (previousKey !== undefined) process.env.IDENTITY_SIGNING_PRIVATE_KEY = previousKey;
      }
    });

    it("loads a configured key ring from the environment", () => {
      configureIdentityKeyRing(null);
      const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
      const previous = generateSigningKey("env-old");
      process.env.IDENTITY_SIGNING_PRIVATE_KEY = privateKey.export({ type: "pkcs8", format: "pem" }).toString().replace(/\n/g, "\\n");
      process.env.IDENTITY_SIGNING_KEY_ID = "env-current";
      process.env.IDENTITY_PREVIOUS_PUBLIC_KEYS = JSON.stringify([toPublicJwk(previous)]);
      try {
        expect(getPublicJwks().keys.map((k) => k.kid)).toEqual(["env-current", "env-old"]);
      } finally {
        delete process.env.IDENTITY_SIGNING_PRIVATE_KEY;
        delete process.env.IDENTITY_SIGNING_KEY_ID;
        delete process.env.IDENTITY_PREVIOUS_PUBLIC_KEYS;
      }
    });

    describe("service authentication", () => {
      it("requires a valid, unrevoked credential of an ACTIVE service with the right scope", async () => {
        const service = await createService("relying-auth", ["identity:introspect"]);
        const u = await makeUser(emails.authority, "APPROVER");

        expect((await serviceCall("/internal/identity-assertions", service.token, { accessToken: u.accessToken })).status).toBe(403);
        expect((await serviceCall("/internal/introspect", "garbage", { assertion: "x" })).status).toBe(401);
        const wrongSecret = service.token.replace(/.$/, (c) => (c === "A" ? "B" : "A"));
        expect((await serviceCall("/internal/introspect", wrongSecret, { assertion: "x" })).status).toBe(401);
        expect((await serviceCall("/internal/introspect", service.token, { assertion: "x" })).status).toBe(200);

        await apiRequest(`/service-accounts/${service.id}/status`, { method: "PATCH", token: superAdmin.token, body: { status: "SUSPENDED" } });
        expect((await serviceCall("/internal/introspect", service.token, { assertion: "x" })).status).toBe(401);
        await apiRequest(`/service-accounts/${service.id}/status`, { method: "PATCH", token: superAdmin.token, body: { status: "ACTIVE" } });

        await apiRequest(`/service-accounts/${service.id}/credentials/${service.credentialId}`, { method: "DELETE", token: superAdmin.token });
        expect((await serviceCall("/internal/introspect", service.token, { assertion: "x" })).status).toBe(401);
      });

      it("stores only a hash of the service secret", async () => {
        const service = await createService("relying-hash");
        const row = await prisma.serviceCredential.findUniqueOrThrow({ where: { id: service.credentialId } });
        expect(service.token).not.toContain(row.secretHash);
        expect(row.secretHash).not.toContain(service.token.split(".")[1]);
      });

      it("a service credential is not a user session and can't reach user or admin routes", async () => {
        const service = await createService("relying-scope");
        for (const path of ["/auth/me", "/users", "/audit"]) {
          const res = await fetch(`${baseUrl}/api${path}`, { headers: { Authorization: `Bearer ${service.token}` } });
          expect(res.status).toBe(401);
        }
      });

      it("an unauthenticated caller can't obtain assertions by sending identity headers", async () => {
        const u = await makeUser(emails.authority, "APPROVER");
        const res = await fetch(`${baseUrl}/api/internal/identity-assertions`, {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-Actor-Id": u.user.id, "X-Actor-Role": "AUTHORITY" },
          body: JSON.stringify({ accessToken: u.accessToken }),
        });
        expect(res.status).toBe(401);
      });

      it("only SUPER_ADMIN manages service accounts", async () => {
        const res = await apiRequest("/service-accounts", { method: "POST", token: admin.token, body: { name: "x", audience: "x", scopes: ["identity:assert"] } });
        expect(res.status).toBe(403);
      });
    });
  });

  describe("session tokens are NovaForge-internal and strictly verified", () => {
    it("rejects a session token with the right secret but the wrong audience or issuer", async () => {
      const u = await makeUser(emails.worker);
      const base = { sub: u.user.id, sessionId: u.session.id, type: "access" };
      const wrongAud = jwt.sign(base, env.jwtAccessSecret, { algorithm: "HS256", issuer: "novaforge", audience: "pashupatastra", expiresIn: 60 });
      const wrongIss = jwt.sign(base, env.jwtAccessSecret, { algorithm: "HS256", issuer: "someone", audience: "novaforge:session", expiresIn: 60 });
      const legacy = jwt.sign(base, env.jwtAccessSecret, { expiresIn: 60 });
      for (const token of [wrongAud, wrongIss, legacy]) {
        expect((await apiRequest("/auth/me", { token })).status).toBe(401);
      }
      expect((await apiRequest("/auth/me", { token: u.accessToken })).status).toBe(200);
    });

    it("rejects an ES256 identity assertion presented as a session token", async () => {
      const service = await createService("relying-confusion");
      const u = await makeUser(emails.worker);
      const { data } = await serviceCall("/internal/identity-assertions", service.token, { accessToken: u.accessToken });
      expect((await apiRequest("/auth/me", { token: data.assertion })).status).toBe(401);
    });
  });
});
