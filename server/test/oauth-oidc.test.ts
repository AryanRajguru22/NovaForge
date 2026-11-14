import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createHash, createPublicKey, randomBytes } from "node:crypto";
import jwt from "jsonwebtoken";
import {
  startTestServer,
  stopTestServer,
  apiRequest,
  createUserWithToken,
  addMockPasskey,
  governanceProof,
  cleanupUsers,
  runSuffix,
} from "./testServer.js";
import { prisma } from "../src/lib/prisma.js";
import { verifyAuditChain } from "../src/lib/audit.js";

// The OIDC provider end to end: registration, authorize + PKCE, token, refresh
// rotation, introspection, the authorization decision API, revocation, logout,
// and the ways each of those must refuse.

const REDIRECT = "https://pp.example.test/auth/callback";
const emails = {
  root: `oidc-root-${runSuffix}@example.com`,
  admin: `oidc-admin-${runSuffix}@example.com`,
  alice: `oidc-alice-${runSuffix}@example.com`,
  bob: `oidc-bob-${runSuffix}@example.com`,
  carol: `oidc-carol-${runSuffix}@example.com`,
};

let baseUrl = "";
let root: { id: string; token: string };
let admin: { id: string; token: string };
let alice: { id: string; token: string; sessionId: string };
let bob: { id: string; token: string };
let carol: { id: string; token: string };
const clientIds: string[] = [];

const pkce = () => {
  const verifier = randomBytes(48).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
};

async function sessionOf(userId: string) {
  return prisma.session.findFirstOrThrow({ where: { userId }, orderBy: { createdAt: "desc" } });
}

interface App {
  id: string;
  clientId: string;
  audience: string;
  secret: string;
  roles: Record<string, string>; // key -> id
}

async function createApp(name: string, extra: Record<string, unknown> = {}): Promise<App> {
  const proof = await governanceProof(root, "app");
  const clientId = `t-${name}-${runSuffix}`.toLowerCase().replace(/[^a-z0-9-]/g, "-").slice(0, 60);
  const res = await apiRequest("/applications", {
    method: "POST",
    token: root.token,
    body: {
      name,
      clientId,
      redirectUris: [REDIRECT],
      postLogoutRedirectUris: ["https://pp.example.test/"],
      audience: `api-${clientId}`,
      permissions: [{ key: "jobs:read" }, { key: "jobs:write" }, { key: "jobs:decide" }],
      roles: [
        { key: "viewer", name: "Viewer", permissions: ["jobs:read"] },
        { key: "approver", name: "Approver", permissions: ["jobs:read", "jobs:write", "jobs:decide"] },
      ],
      ...extra,
      response: proof,
    },
  });
  expect(res.status, JSON.stringify(res.data)).toBe(201);
  clientIds.push(res.data.application.id);
  const detail = await apiRequest(`/applications/${res.data.application.id}`, { token: root.token });
  const roles = Object.fromEntries(detail.data.roles.map((r: { key: string; id: string }) => [r.key, r.id]));
  return { id: res.data.application.id, clientId, audience: res.data.application.audience, secret: res.data.secret.value, roles };
}

async function assign(app: App, userId: string, roleKey: string, extra: Record<string, unknown> = {}) {
  const proof = await governanceProof(root, "app");
  return apiRequest(`/applications/${app.id}/assignments`, {
    method: "POST",
    token: root.token,
    body: { userId, roleId: app.roles[roleKey], ...extra, response: proof },
  });
}

async function authorize(
  app: App,
  user: { token: string } | null,
  overrides: Record<string, string | undefined> = {},
  pk = pkce(),
) {
  const params: Record<string, string | undefined> = {
    client_id: app.clientId,
    redirect_uri: REDIRECT,
    response_type: "code",
    scope: "openid profile email roles offline_access",
    state: "state-" + randomBytes(6).toString("hex"),
    nonce: "nonce-" + randomBytes(6).toString("hex"),
    code_challenge: pk.challenge,
    code_challenge_method: "S256",
    ...overrides,
  };
  const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined) as [string, string][]);
  const res = await fetch(`${baseUrl}/api/oauth/authorize?${qs}`, {
    redirect: "manual",
    headers: user ? { Cookie: `accessToken=${user.token}` } : {},
  });
  const location = res.headers.get("location");
  return { res, params, pk, location, url: location ? new URL(location) : null };
}

const basic = (app: App, secret = app.secret) => "Basic " + Buffer.from(`${app.clientId}:${secret}`).toString("base64");

async function tokenRequest(app: App, form: Record<string, string>, auth: string | null = basic(app)) {
  const res = await fetch(`${baseUrl}/api/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", ...(auth ? { Authorization: auth } : {}) },
    body: new URLSearchParams(form),
  });
  return { status: res.status, data: (await res.json()) as any, headers: res.headers };
}

async function formPost(path: string, app: App, form: Record<string, string>, auth: string | null = basic(app)) {
  const res = await fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", ...(auth ? { Authorization: auth } : {}) },
    body: new URLSearchParams(form),
  });
  return { status: res.status, data: (await res.json()) as any };
}

/** Runs authorize + code exchange and returns the tokens. */
async function signIn(app: App, user: { token: string }, overrides: Record<string, string | undefined> = {}) {
  const a = await authorize(app, user, overrides);
  expect(a.url?.searchParams.get("code"), a.location ?? "no redirect").toBeTruthy();
  const code = a.url!.searchParams.get("code")!;
  const t = await tokenRequest(app, { grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: a.pk.verifier });
  expect(t.status, JSON.stringify(t.data)).toBe(200);
  return { ...a, tokens: t.data, code };
}

describe("OIDC provider", () => {
  let appA: App;
  let appB: App;

  beforeAll(async () => {
    baseUrl = await startTestServer();
    const r = await createUserWithToken({ email: emails.root, role: "SUPER_ADMIN", name: "Root Admin" });
    root = { id: r.user.id, token: r.token };
    await addMockPasskey(root.id);
    const a = await createUserWithToken({ email: emails.admin, role: "ADMIN" });
    admin = { id: a.user.id, token: a.token };
    await addMockPasskey(admin.id);
    const al = await createUserWithToken({ email: emails.alice, name: "Alice Example" });
    alice = { id: al.user.id, token: al.token, sessionId: (await sessionOf(al.user.id)).id };
    const bb = await createUserWithToken({ email: emails.bob });
    bob = { id: bb.user.id, token: bb.token };
    const c = await createUserWithToken({ email: emails.carol });
    carol = { id: c.user.id, token: c.token };

    appA = await createApp("app-a");
    appB = await createApp("app-b");
    expect((await assign(appA, alice.id, "approver")).status).toBe(201);
    expect((await assign(appB, bob.id, "viewer")).status).toBe(201);
  });

  afterAll(async () => {
    await prisma.oAuthClient.deleteMany({ where: { id: { in: clientIds } } });
    await cleanupUsers([emails.root, emails.admin, emails.alice, emails.bob, emails.carol]);
    await stopTestServer();
  });

  describe("registration and discovery", () => {
    it("publishes a discovery document whose endpoints and issuer match the tokens", async () => {
      const doc = await (await fetch(`${baseUrl}/.well-known/openid-configuration`)).json();
      const alt = await (await fetch(`${baseUrl}/api/.well-known/openid-configuration`)).json();
      expect(alt).toEqual(doc);
      expect(doc.code_challenge_methods_supported).toEqual(["S256"]);
      expect(doc.authorization_endpoint).toBe(`${doc.issuer}/api/oauth/authorize`);
      expect(doc.jwks_uri).toBe(`${doc.issuer}/.well-known/jwks.json`);
      const { tokens } = await signIn(appA, alice);
      expect(jwt.decode(tokens.id_token)).toMatchObject({ iss: doc.issuer });
    });

    it("sets open CORS (no credentials) on discovery and token, but not on admin APIs", async () => {
      const disc = await fetch(`${baseUrl}/.well-known/openid-configuration`, { headers: { Origin: "https://elsewhere.test" } });
      expect(disc.headers.get("access-control-allow-origin")).toBe("*");
      expect(disc.headers.get("access-control-allow-credentials")).toBeNull();
      const admin = await fetch(`${baseUrl}/api/applications`, { headers: { Origin: "https://elsewhere.test" } });
      expect(admin.headers.get("access-control-allow-origin")).not.toBe("*");
    });

    it("requires step-up, SUPER_ADMIN and sane redirect URIs to register an application", async () => {
      const noProof = await apiRequest("/applications", { method: "POST", token: root.token, body: { name: "x", redirectUris: [REDIRECT] } });
      expect(noProof.status).toBe(403);
      expect(noProof.data.code).toBe("STEP_UP_REQUIRED");

      const asAdmin = await apiRequest("/applications", { method: "POST", token: admin.token, body: { name: "x", redirectUris: [REDIRECT], response: {} } });
      expect(asAdmin.status).toBe(403);
      expect((await apiRequest("/applications/step-up/options", { method: "POST", token: admin.token, body: {} })).status).toBe(403);

      for (const bad of ["https://*.example.test/cb", "http://pp.example.test/cb", "https://pp.example.test/cb#frag", "javascript:alert(1)", "https://user:pw@pp.example.test/cb", "https://pp.example.test"]) {
        const res = await apiRequest("/applications", {
          method: "POST",
          token: root.token,
          body: { name: "bad", redirectUris: [bad], response: await governanceProof(root, "app") },
        });
        expect(res.status, bad).toBe(400);
      }
      const loopback = await apiRequest("/applications", {
        method: "POST",
        token: root.token,
        body: { name: "local", clientId: `t-local-${runSuffix}`.toLowerCase(), redirectUris: ["http://localhost:3000/cb"], response: await governanceProof(root, "app") },
      });
      expect(loopback.status).toBe(201);
      clientIds.push(loopback.data.application.id);
    });

    it("returns the secret exactly once and never exposes it or its hash afterwards", async () => {
      expect(appA.secret).toMatch(/^nfcs_/);
      const detail = await apiRequest(`/applications/${appA.id}`, { token: admin.token });
      expect(detail.status).toBe(200);
      expect(JSON.stringify(detail.data)).not.toContain(appA.secret);
      expect(JSON.stringify(detail.data)).not.toMatch(/secretHash/);
      const row = await prisma.oAuthClientSecret.findFirstOrThrow({ where: { clientId: appA.id } });
      expect(row.secretHash).not.toContain(appA.secret);
    });

    it("lets ADMIN read but not write, and refuses members entirely", async () => {
      expect((await apiRequest("/applications", { token: admin.token })).status).toBe(200);
      expect((await apiRequest("/applications", { token: alice.token })).status).toBe(403);
      expect((await apiRequest("/applications")).status).toBe(401);
      const patch = await apiRequest(`/applications/${appA.id}`, { method: "PATCH", token: admin.token, body: { name: "hax", response: {} } });
      expect(patch.status).toBe(403);
    });
  });

  describe("authorization endpoint", () => {
    it("never redirects for an unknown client or an unregistered redirect_uri", async () => {
      const unknown = await authorize({ ...appA, clientId: "nope" }, alice);
      expect(unknown.res.status).toBe(400);
      expect(unknown.location).toBeNull();
      for (const uri of ["https://evil.example.test/cb", REDIRECT + "/", REDIRECT + "?x=1", REDIRECT.toUpperCase(), "https://pp.example.test/auth/callback#x"]) {
        const r = await authorize(appA, alice, { redirect_uri: uri });
        expect(r.res.status, uri).toBe(400);
        expect(r.location, uri).toBeNull();
      }
      const html = await (await authorize(appA, alice, { redirect_uri: "https://evil.example.test/<script>" })).res.text();
      expect(html).not.toContain("<script>");
    });

    it("rejects malformed requests by redirecting an error (with iss) to the registered URI", async () => {
      const cases: [Record<string, string | undefined>, string][] = [
        [{ response_type: "token" }, "unsupported_response_type"],
        [{ state: undefined }, "invalid_request"],
        [{ nonce: undefined }, "invalid_request"],
        [{ code_challenge: undefined }, "invalid_request"],
        [{ code_challenge_method: "plain" }, "invalid_request"],
        [{ code_challenge: "short" }, "invalid_request"],
        [{ scope: "profile" }, "invalid_scope"],
        [{ scope: "openid admin" }, "invalid_scope"],
        [{ prompt: "login" }, "invalid_request"],
      ];
      for (const [override, error] of cases) {
        const r = await authorize(appA, alice, override);
        expect(r.res.status).toBe(302);
        expect(r.url!.origin + r.url!.pathname, JSON.stringify(override)).toBe(REDIRECT);
        expect(r.url!.searchParams.get("error"), JSON.stringify(override)).toBe(error);
        expect(r.url!.searchParams.get("iss")).toBeTruthy();
        expect(r.url!.searchParams.get("code")).toBeNull();
      }
    });

    it("sends an unauthenticated browser to NovaForge's own sign-in, and honours prompt=none", async () => {
      const r = await authorize(appA, null);
      expect(r.res.status).toBe(302);
      expect(r.url!.pathname).toBe("/oauth/signin");
      expect(r.url!.searchParams.get("client_id")).toBe(appA.clientId);
      const none = await authorize(appA, null, { prompt: "none" });
      expect(none.url!.searchParams.get("error")).toBe("login_required");
    });

    it("denies by default: a user holding no role in the application gets access_denied", async () => {
      const r = await authorize(appA, carol);
      expect(r.url!.searchParams.get("error")).toBe("access_denied");
      expect(r.url!.searchParams.get("code")).toBeNull();
      expect(await prisma.oAuthGrant.count({ where: { userId: carol.id } })).toBe(0);
    });

    it("rejects parameters supplied twice", async () => {
      const pk = pkce();
      const qs = `client_id=${appA.clientId}&redirect_uri=${encodeURIComponent(REDIRECT)}&redirect_uri=${encodeURIComponent("https://evil.example.test/cb")}&response_type=code&scope=openid&state=s&nonce=n&code_challenge=${pk.challenge}&code_challenge_method=S256`;
      const res = await fetch(`${baseUrl}/api/oauth/authorize?${qs}`, { redirect: "manual", headers: { Cookie: `accessToken=${alice.token}` } });
      expect(res.status).toBe(400);
      expect(res.headers.get("location")).toBeNull();
    });
  });

  describe("token issuance", () => {
    it("issues verifiable ID and access tokens bound to nonce, audience and client", async () => {
      const { tokens, params, url } = await signIn(appA, alice);
      expect(url!.searchParams.get("state")).toBe(params.state);
      expect(tokens.token_type).toBe("Bearer");
      expect(tokens.refresh_token).toMatch(/^nfrt_/);

      const jwks = await (await fetch(`${baseUrl}/.well-known/jwks.json`)).json();
      const idHeader = jwt.decode(tokens.id_token, { complete: true })!.header as { kid: string; typ: string };
      const key = createPublicKey({ key: jwks.keys.find((k: { kid: string }) => k.kid === idHeader.kid), format: "jwk" });
      const id = jwt.verify(tokens.id_token, key, { algorithms: ["ES256"], audience: appA.clientId }) as jwt.JwtPayload;
      expect(idHeader.typ).toBe("JWT");
      expect(id).toMatchObject({ sub: alice.id, nonce: params.nonce, token_use: "id_token", principal_type: "user", account_status: "ACTIVE", name: "Alice Example" });
      expect(id.exp! - id.iat!).toBeLessThanOrEqual(300);
      expect(id.at_hash).toBe(createHash("sha256").update(tokens.access_token).digest().subarray(0, 16).toString("base64url"));

      const atHeader = jwt.decode(tokens.access_token, { complete: true })!.header as { typ: string };
      const at = jwt.verify(tokens.access_token, key, { algorithms: ["ES256"], audience: appA.audience }) as jwt.JwtPayload;
      expect(atHeader.typ).toBe("at+jwt");
      expect(at).toMatchObject({ sub: alice.id, client_id: appA.clientId, token_use: "access_token", roles: ["approver"] });
      expect(at.permissions).toEqual(["jobs:decide", "jobs:read", "jobs:write"]);
      // An access token is not an ID token and vice versa.
      expect(() => jwt.verify(tokens.access_token, key, { algorithms: ["ES256"], audience: appA.clientId })).toThrow();
      expect(id.token_use).not.toBe(at.token_use);
    });

    it("authenticates the client: wrong, missing, revoked and other-client secrets all fail", async () => {
      const a = await authorize(appA, alice);
      const code = a.url!.searchParams.get("code")!;
      const form = { grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: a.pk.verifier };
      expect((await tokenRequest(appA, form, basic(appA, "nfcs_" + "A".repeat(43)))).status).toBe(401);
      expect((await tokenRequest(appA, form, null)).status).toBe(401);
      expect((await tokenRequest(appA, form, basic(appA, appB.secret))).status).toBe(401);
      expect((await tokenRequest(appA, form, basic({ ...appA, clientId: "unknown" }))).status).toBe(401);
      // The code survived all of that and still redeems with the right credentials.
      expect((await tokenRequest(appA, form)).status).toBe(200);
    });

    it("binds the code to the client, redirect_uri and PKCE verifier, and burns it on a failed attempt", async () => {
      // wrong verifier
      const a = await authorize(appA, alice);
      const code = a.url!.searchParams.get("code")!;
      const bad = await tokenRequest(appA, { grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: pkce().verifier });
      expect(bad).toMatchObject({ status: 400, data: { error: "invalid_grant" } });
      // the genuine verifier no longer works: the code was consumed by the failed attempt
      const retry = await tokenRequest(appA, { grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: a.pk.verifier });
      expect(retry.status).toBe(400);

      // redirect_uri mismatch
      const b = await authorize(appA, alice);
      const mismatch = await tokenRequest(appA, {
        grant_type: "authorization_code",
        code: b.url!.searchParams.get("code")!,
        redirect_uri: "https://pp.example.test/other",
        code_verifier: b.pk.verifier,
      });
      expect(mismatch.data.error).toBe("invalid_grant");

      // another client presenting appA's code
      const c = await authorize(appA, alice);
      const stolen = await tokenRequest(appB, {
        grant_type: "authorization_code",
        code: c.url!.searchParams.get("code")!,
        redirect_uri: REDIRECT,
        code_verifier: c.pk.verifier,
      });
      expect(stolen.data.error).toBe("invalid_grant");
    });

    it("refuses an expired code", async () => {
      const a = await authorize(appA, alice);
      const code = a.url!.searchParams.get("code")!;
      await prisma.authorizationCode.updateMany({ where: { codeHash: createHash("sha256").update(code).digest("hex") }, data: { expiresAt: new Date(Date.now() - 1000) } });
      const t = await tokenRequest(appA, { grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: a.pk.verifier });
      expect(t.data.error).toBe("invalid_grant");
    });

    it("treats replay of a redeemed code as theft and revokes what it produced", async () => {
      const s = await signIn(appA, alice);
      const replay = await tokenRequest(appA, { grant_type: "authorization_code", code: s.code, redirect_uri: REDIRECT, code_verifier: s.pk.verifier });
      expect(replay.status).toBe(400);
      const live = await formPost("/api/oauth/introspect", appA, { token: s.tokens.access_token });
      expect(live.data.active).toBe(false);
      const refresh = await tokenRequest(appA, { grant_type: "refresh_token", refresh_token: s.tokens.refresh_token });
      expect(refresh.status).toBe(400);
    });

    it("allows only one of many concurrent redemptions of the same code", async () => {
      const a = await authorize(appA, alice);
      const form = { grant_type: "authorization_code", code: a.url!.searchParams.get("code")!, redirect_uri: REDIRECT, code_verifier: a.pk.verifier };
      const results = await Promise.all(Array.from({ length: 6 }, () => tokenRequest(appA, form)));
      expect(results.filter((r) => r.status === 200)).toHaveLength(1);
    });

    it("does not cache token responses", async () => {
      const a = await authorize(appA, alice);
      const t = await tokenRequest(appA, { grant_type: "authorization_code", code: a.url!.searchParams.get("code")!, redirect_uri: REDIRECT, code_verifier: a.pk.verifier });
      expect(t.headers.get("cache-control")).toBe("no-store");
    });

    it("rejects unsupported grants", async () => {
      expect((await tokenRequest(appA, { grant_type: "password", username: "a", password: "b" })).data.error).toBe("unsupported_grant_type");
      expect((await tokenRequest(appA, { grant_type: "client_credentials" })).data.error).toBe("unsupported_grant_type");
    });
  });

  describe("refresh tokens", () => {
    it("rotates on every use and detects reuse of a spent token by revoking the whole grant", async () => {
      const s = await signIn(appA, alice);
      const first = await tokenRequest(appA, { grant_type: "refresh_token", refresh_token: s.tokens.refresh_token });
      expect(first.status).toBe(200);
      expect(first.data.refresh_token).not.toBe(s.tokens.refresh_token);
      expect(first.data.access_token).toBeTruthy();

      // The new access token works...
      expect((await formPost("/api/oauth/introspect", appA, { token: first.data.access_token })).data.active).toBe(true);
      // ...until the OLD refresh token is replayed: that kills the family, including the newest tokens.
      const reuse = await tokenRequest(appA, { grant_type: "refresh_token", refresh_token: s.tokens.refresh_token });
      expect(reuse.status).toBe(400);
      expect((await formPost("/api/oauth/introspect", appA, { token: first.data.access_token })).data.active).toBe(false);
      expect((await tokenRequest(appA, { grant_type: "refresh_token", refresh_token: first.data.refresh_token })).status).toBe(400);
      expect(await prisma.auditLog.count({ where: { event: "OAUTH_REFRESH_REUSE_DETECTED" } })).toBeGreaterThan(0);
    });

    it("lets only one of several concurrent refreshes through", async () => {
      const s = await signIn(appA, alice);
      const results = await Promise.all(Array.from({ length: 5 }, () => tokenRequest(appA, { grant_type: "refresh_token", refresh_token: s.tokens.refresh_token })));
      expect(results.filter((r) => r.status === 200).length).toBe(1);
    });

    it("will not honour another client's refresh token", async () => {
      const s = await signIn(appA, alice);
      expect((await tokenRequest(appB, { grant_type: "refresh_token", refresh_token: s.tokens.refresh_token })).status).toBe(400);
      expect((await tokenRequest(appA, { grant_type: "refresh_token", refresh_token: "nfrt_" + "x".repeat(43) })).status).toBe(400);
      expect((await tokenRequest(appA, { grant_type: "refresh_token", refresh_token: "garbage" })).status).toBe(400);
    });

    it("refuses refresh after the token expired", async () => {
      const s = await signIn(appA, alice);
      await prisma.oAuthRefreshToken.updateMany({ where: { tokenHash: createHash("sha256").update(s.tokens.refresh_token).digest("hex") }, data: { expiresAt: new Date(Date.now() - 1000) } });
      expect((await tokenRequest(appA, { grant_type: "refresh_token", refresh_token: s.tokens.refresh_token })).status).toBe(400);
    });
  });

  describe("introspection, userinfo and the decision API", () => {
    it("reports live roles and permissions, only to the client the token was issued to", async () => {
      const s = await signIn(appA, alice);
      const mine = await formPost("/api/oauth/introspect", appA, { token: s.tokens.access_token });
      expect(mine.data).toMatchObject({ active: true, sub: alice.id, client_id: appA.clientId, aud: appA.audience, roles: ["approver"], email: emails.alice });
      // Another application learns nothing: same answer as for garbage.
      expect((await formPost("/api/oauth/introspect", appB, { token: s.tokens.access_token })).data).toEqual({ active: false });
      expect((await formPost("/api/oauth/introspect", appA, { token: "not-a-token" })).data).toEqual({ active: false });
      expect((await formPost("/api/oauth/introspect", appA, { token: s.tokens.access_token }, null)).status).toBe(401);
      // An ID token is not an access token.
      expect((await formPost("/api/oauth/introspect", appA, { token: s.tokens.id_token })).data.active).toBe(false);
    });

    it("serves userinfo for a bearer access token and nothing for anything else", async () => {
      const s = await signIn(appA, alice);
      const ok = await fetch(`${baseUrl}/api/oauth/userinfo`, { headers: { Authorization: `Bearer ${s.tokens.access_token}` } });
      expect(await ok.json()).toMatchObject({ sub: alice.id, name: "Alice Example", roles: ["approver"] });
      expect((await fetch(`${baseUrl}/api/oauth/userinfo`)).status).toBe(401);
      expect((await fetch(`${baseUrl}/api/oauth/userinfo`, { headers: { Authorization: `Bearer ${s.tokens.id_token}` } })).status).toBe(401);
      expect((await fetch(`${baseUrl}/api/oauth/userinfo`, { headers: { Authorization: "Bearer a.b.c" } })).status).toBe(401);
    });

    it("answers authorization questions from the database, default-deny, with tenant isolation", async () => {
      const s = await signIn(appA, alice);
      const check = (app: App, body: object, auth: string | null = basic(app)) =>
        fetch(`${baseUrl}/api/v1/authz/check`, {
          method: "POST",
          headers: { "Content-Type": "application/json", ...(auth ? { Authorization: auth } : {}) },
          body: JSON.stringify(body),
        }).then(async (r) => ({ status: r.status, data: (await r.json()) as any }));

      const yes = await check(appA, { token: s.tokens.access_token, permission: "jobs:decide" });
      expect(yes.data).toMatchObject({ active: true, allowed: true, sub: alice.id });
      const no = await check(appA, { token: s.tokens.access_token, permission: "jobs:delete" });
      expect(no.data.allowed).toBe(false);
      const batch = await check(appA, { token: s.tokens.access_token, checks: [{ permission: "jobs:read" }, { permission: "jobs:admin" }] });
      expect(batch.data.decisions.map((d: { allowed: boolean }) => d.allowed)).toEqual([true, false]);
      expect(batch.data.allowed).toBe(false);

      // another application can neither ask about nor learn from this token
      expect((await check(appB, { token: s.tokens.access_token, permission: "jobs:read" })).data).toMatchObject({ active: false, allowed: false });
      // malformed input and unauthenticated callers
      expect((await check(appA, { token: s.tokens.access_token })).status).toBe(400);
      expect((await check(appA, { token: s.tokens.access_token, permission: "Not Valid!" })).status).toBe(400);
      expect((await check(appA, { token: s.tokens.access_token, permission: "jobs:read" }, null)).status).toBe(401);
      expect((await check(appA, { token: "junk", permission: "jobs:read" })).data.allowed).toBe(false);
    });

    it("applies resource-scoped assignments only to matching resources", async () => {
      const dave = await createUserWithToken({ email: `oidc-dave-${runSuffix}@example.com` });
      await (assign(appA, dave.user.id, "approver", { resource: "corridor/NDLS-AGC/*" }));
      const s = await signIn(appA, dave);
      const check = (b: object) =>
        fetch(`${baseUrl}/api/v1/authz/check`, { method: "POST", headers: { "Content-Type": "application/json", Authorization: basic(appA) }, body: JSON.stringify({ token: s.tokens.access_token, ...b }) }).then((r) => r.json()) as Promise<any>;
      expect((await check({ permission: "jobs:decide", resource: "corridor/NDLS-AGC/section-1" })).allowed).toBe(true);
      expect((await check({ permission: "jobs:decide", resource: "corridor/NDLS-AGC" })).allowed).toBe(true);
      expect((await check({ permission: "jobs:decide", resource: "corridor/NDLS-AGCX/section-1" })).allowed).toBe(false);
      expect((await check({ permission: "jobs:decide", resource: "corridor/OTHER" })).allowed).toBe(false);
      // a resource-limited role is not an application-wide permission
      expect((await check({ permission: "jobs:decide" })).allowed).toBe(false);
      expect((await formPost("/api/oauth/introspect", appA, { token: s.tokens.access_token })).data.permissions).toEqual([]);
      await cleanupUsers([`oidc-dave-${runSuffix}@example.com`]);
    });
  });

  describe("revocation and liveness", () => {
    it("takes effect immediately when an administrator changes or removes a role", async () => {
      const eve = await createUserWithToken({ email: `oidc-eve-${runSuffix}@example.com` });
      const viewer = (await assign(appA, eve.user.id, "viewer")).data;
      const s = await signIn(appA, eve);
      const intro = () => formPost("/api/oauth/introspect", appA, { token: s.tokens.access_token }).then((r) => r.data);
      expect(await intro()).toMatchObject({ active: true, roles: ["viewer"], permissions: ["jobs:read"] });

      // promote
      expect((await assign(appA, eve.user.id, "approver")).status).toBe(201);
      expect(await intro()).toMatchObject({ roles: ["approver", "viewer"], permissions: ["jobs:decide", "jobs:read", "jobs:write"] });

      // remove everything: default-deny means the grant stops being usable at once
      const list = await apiRequest(`/applications/${appA.id}/assignments?search=oidc-eve`, { token: root.token });
      for (const item of list.data.items) {
        const del = await apiRequest(`/applications/${appA.id}/assignments/${item.id}`, { method: "DELETE", token: root.token, body: { response: await governanceProof(root, "app") } });
        expect(del.status).toBe(200);
      }
      expect(await intro()).toEqual({ active: false });
      expect((await tokenRequest(appA, { grant_type: "refresh_token", refresh_token: s.tokens.refresh_token })).status).toBe(400);
      expect(viewer.id).toBeTruthy();
      await cleanupUsers([`oidc-eve-${runSuffix}@example.com`]);
    });

    it("ends every grant when the NovaForge session is revoked or the user is disabled", async () => {
      const fay = await createUserWithToken({ email: `oidc-fay-${runSuffix}@example.com` });
      await assign(appA, fay.user.id, "viewer");
      const s1 = await signIn(appA, fay);
      const intro = (t: string) => formPost("/api/oauth/introspect", appA, { token: t }).then((r) => r.data.active);
      expect(await intro(s1.tokens.access_token)).toBe(true);
      await prisma.session.deleteMany({ where: { userId: fay.user.id } });
      expect(await intro(s1.tokens.access_token)).toBe(false);
      expect((await tokenRequest(appA, { grant_type: "refresh_token", refresh_token: s1.tokens.refresh_token })).status).toBe(400);

      // disabled account
      const gus = await createUserWithToken({ email: `oidc-gus-${runSuffix}@example.com` });
      await assign(appA, gus.user.id, "viewer");
      const s2 = await signIn(appA, gus);
      await prisma.user.update({ where: { id: gus.user.id }, data: { status: "SUSPENDED" } });
      expect(await intro(s2.tokens.access_token)).toBe(false);
      expect((await tokenRequest(appA, { grant_type: "refresh_token", refresh_token: s2.tokens.refresh_token })).status).toBe(400);
      await cleanupUsers([`oidc-fay-${runSuffix}@example.com`, `oidc-gus-${runSuffix}@example.com`]);
    });

    it("stops serving a disabled application and revokes what it held", async () => {
      const app = await createApp("app-disable");
      const hal = await createUserWithToken({ email: `oidc-hal-${runSuffix}@example.com` });
      await assign(app, hal.user.id, "viewer");
      const s = await signIn(app, hal);
      const res = await apiRequest(`/applications/${app.id}`, { method: "PATCH", token: root.token, body: { status: "DISABLED", response: await governanceProof(root, "app") } });
      expect(res.status).toBe(200);
      expect((await formPost("/api/oauth/introspect", app, { token: s.tokens.access_token })).status).toBe(401); // client can no longer authenticate
      expect((await authorize(app, hal)).res.status).toBe(400);
      expect((await tokenRequest(app, { grant_type: "refresh_token", refresh_token: s.tokens.refresh_token })).status).toBe(401);
      await cleanupUsers([`oidc-hal-${runSuffix}@example.com`]);
    });

    it("revokes a grant when the application asks (RFC 7009) and never reveals whether a token existed", async () => {
      const s = await signIn(appA, alice);
      const unknown = await formPost("/api/oauth/revoke", appA, { token: "nfrt_" + "z".repeat(43) });
      expect(unknown.status).toBe(200);
      // another client cannot revoke it
      await formPost("/api/oauth/revoke", appB, { token: s.tokens.refresh_token });
      expect((await formPost("/api/oauth/introspect", appA, { token: s.tokens.access_token })).data.active).toBe(true);
      expect((await formPost("/api/oauth/revoke", appA, { token: s.tokens.refresh_token })).status).toBe(200);
      expect((await formPost("/api/oauth/introspect", appA, { token: s.tokens.access_token })).data.active).toBe(false);
    });

    it("lets an administrator revoke a live grant", async () => {
      const s = await signIn(appA, alice);
      const grants = await apiRequest(`/applications/${appA.id}/grants`, { token: admin.token });
      expect(grants.status).toBe(200);
      const sid = (jwt.decode(s.tokens.access_token) as { sid: string }).sid;
      expect(grants.data.items.some((g: { id: string }) => g.id === sid)).toBe(true);
      const del = await apiRequest(`/applications/${appA.id}/grants/${sid}`, { method: "DELETE", token: root.token });
      expect(del.status).toBe(200);
      expect((await formPost("/api/oauth/introspect", appA, { token: s.tokens.access_token })).data.active).toBe(false);
    });
  });

  describe("logout", () => {
    it("signs out of NovaForge too, and only redirects to a registered post-logout URI", async () => {
      const ivy = await createUserWithToken({ email: `oidc-ivy-${runSuffix}@example.com` });
      await assign(appA, ivy.user.id, "viewer");
      const s = await signIn(appA, ivy);
      const evil = await fetch(`${baseUrl}/api/oauth/logout?${new URLSearchParams({ id_token_hint: s.tokens.id_token, post_logout_redirect_uri: "https://evil.example.test/" })}`, { redirect: "manual", headers: { Cookie: `accessToken=${ivy.token}` } });
      expect(evil.status).toBe(400);
      expect(await prisma.session.count({ where: { userId: ivy.user.id } })).toBe(1);

      const ok = await fetch(`${baseUrl}/api/oauth/logout?${new URLSearchParams({ id_token_hint: s.tokens.id_token, post_logout_redirect_uri: "https://pp.example.test/", state: "xyz" })}`, { redirect: "manual", headers: { Cookie: `accessToken=${ivy.token}` } });
      expect(ok.status).toBe(302);
      expect(ok.headers.get("location")).toBe("https://pp.example.test/?state=xyz");
      expect(await prisma.session.count({ where: { userId: ivy.user.id } })).toBe(0);
      expect((await formPost("/api/oauth/introspect", appA, { token: s.tokens.access_token })).data.active).toBe(false);
      await cleanupUsers([`oidc-ivy-${runSuffix}@example.com`]);
    });

    it("never ends someone else's session on the strength of an id_token_hint alone", async () => {
      const s = await signIn(appA, alice);
      const res = await fetch(`${baseUrl}/api/oauth/logout?${new URLSearchParams({ id_token_hint: s.tokens.id_token })}`, { redirect: "manual" });
      expect(res.status).toBe(302);
      expect(await prisma.session.count({ where: { userId: alice.id } })).toBeGreaterThan(0);
      // the RP's grant is revoked, but the user's NovaForge session (no cookie presented) is untouched
      expect((await formPost("/api/oauth/introspect", appA, { token: s.tokens.access_token })).data.active).toBe(false);
    });
  });

  describe("authorization data integrity", () => {
    it("forbids assigning roles to yourself, across applications, or to inactive users", async () => {
      expect((await assign(appA, root.id, "viewer")).status).toBe(403);
      // appB's role cannot be assigned inside appA
      const cross = await assign(appA, bob.id, "viewer");
      expect(cross.status).toBe(201);
      const crossRole = await apiRequest(`/applications/${appA.id}/assignments`, {
        method: "POST",
        token: root.token,
        body: { userId: bob.id, roleId: appB.roles.viewer, response: await governanceProof(root, "app") },
      });
      expect(crossRole.status).toBe(404);
      // the database refuses it even if the API were bypassed
      await expect(prisma.appRoleAssignment.create({ data: { clientId: appA.id, roleId: appB.roles.viewer, userId: bob.id, resource: "x" } })).rejects.toThrow();
      const inactive = await createUserWithToken({ email: `oidc-off-${runSuffix}@example.com` });
      await prisma.user.update({ where: { id: inactive.user.id }, data: { status: "DISABLED" } });
      expect((await assign(appA, inactive.user.id, "viewer")).status).toBe(404);
      await cleanupUsers([`oidc-off-${runSuffix}@example.com`]);
    });

    it("rejects malformed resources, expired assignments and duplicate definitions", async () => {
      expect((await assign(appA, carol.id, "viewer", { resource: "a b" })).status).toBe(400);
      expect((await assign(appA, carol.id, "viewer", { resource: "../etc" })).status).toBe(400);
      expect((await assign(appA, carol.id, "viewer", { expiresAt: new Date(Date.now() - 1000).toISOString() })).status).toBe(400);
      const dup = await apiRequest(`/applications/${appA.id}/permissions`, { method: "POST", token: root.token, body: { key: "jobs:read" } });
      expect(dup.status).toBe(409);
    });

    it("ignores expired assignments", async () => {
      const kim = await createUserWithToken({ email: `oidc-kim-${runSuffix}@example.com` });
      const created = await assign(appA, kim.user.id, "viewer", { expiresAt: new Date(Date.now() + 120_000).toISOString() });
      expect(created.status).toBe(201);
      const s = await signIn(appA, kim);
      await prisma.appRoleAssignment.update({ where: { id: created.data.id }, data: { expiresAt: new Date(Date.now() - 1000) } });
      expect((await formPost("/api/oauth/introspect", appA, { token: s.tokens.access_token })).data.active).toBe(false);
      await cleanupUsers([`oidc-kim-${runSuffix}@example.com`]);
    });

    it("rotates credentials without downtime: both secrets work until the old one is revoked", async () => {
      const issued = await apiRequest(`/applications/${appB.id}/secrets`, { method: "POST", token: root.token, body: { label: "rotation", response: await governanceProof(root, "app") } });
      expect(issued.status).toBe(201);
      const next = issued.data.secret as string;
      const probe = async (secret: string) => (await formPost("/api/oauth/introspect", appB, { token: "x" }, basic(appB, secret))).status;
      expect(await probe(appB.secret)).toBe(200);
      expect(await probe(next)).toBe(200);
      const first = await prisma.oAuthClientSecret.findFirstOrThrow({ where: { clientId: appB.id }, orderBy: { createdAt: "asc" } });
      const del = await apiRequest(`/applications/${appB.id}/secrets/${first.id}`, { method: "DELETE", token: root.token, body: { response: await governanceProof(root, "app") } });
      expect(del.status).toBe(200);
      expect(await probe(appB.secret)).toBe(401);
      expect(await probe(next)).toBe(200);
      appB.secret = next;
    });

    it("keeps the tamper-evident audit chain intact and records the security-sensitive operations", async () => {
      const verification = await verifyAuditChain();
      expect(verification.valid, JSON.stringify(verification.issues?.slice(0, 3))).toBe(true);
      const events = new Set((await prisma.auditLog.findMany({ where: { event: { startsWith: "APP" } }, select: { event: true } })).map((e) => e.event));
      for (const e of ["APPLICATION_CREATED", "APP_ROLE_ASSIGNED", "APP_ROLE_REVOKED", "APPLICATION_SECRET_ISSUED", "APPLICATION_SECRET_REVOKED", "APPLICATION_STATUS_CHANGED"]) {
        expect(events.has(e), e).toBe(true);
      }
      const oauth = new Set((await prisma.auditLog.findMany({ where: { event: { startsWith: "OAUTH" } }, select: { event: true } })).map((e) => e.event));
      for (const e of ["OAUTH_CODE_ISSUED", "OAUTH_TOKENS_ISSUED", "OAUTH_ACCESS_DENIED", "OAUTH_CODE_REPLAY_DETECTED", "OAUTH_GRANT_REVOKED"]) {
        expect(oauth.has(e), e).toBe(true);
      }
      expect(JSON.stringify((await prisma.auditLog.findMany({ where: { event: { startsWith: "APP" } } })).map((r) => r.metadata))).not.toContain(appA.secret);
    });
  });
});
