import { createHash, timingSafeEqual } from "node:crypto";
import { Router, type Request, type Response } from "express";
import { randomBytes } from "node:crypto";
import { Prisma, type OAuthClient } from "@prisma/client";
import { prisma } from "../lib/prisma.js";
import { env } from "../lib/env.js";
import { sha256Hex } from "../lib/canonicalJson.js";
import { verifyAccessToken } from "../lib/jwt.js";
import { appendAuditLog, auditedTransaction } from "../lib/audit.js";
import { isSessionLive } from "../middleware/requireAuth.js";
import { rateLimit } from "../middleware/rateLimit.js";
import { IdentityKeysUnavailableError } from "../lib/identityKeys.js";
import { AUTH_CODE_TTL_SEC, SUPPORTED_SCOPES, discoveryDocument, issuer } from "../lib/oauth/config.js";
import { authenticateClient } from "../lib/oauth/clientAuth.js";
import { hasAnyAccess, isPermitted, isValidResource, loadAccess, PERMISSION_KEY } from "../lib/oauth/rbac.js";
import {
  claimsForScope,
  isWellFormedRefreshToken,
  issueTokenSet,
  liveGrantFor,
  revokeGrant,
  verifyAccessTokenJwt,
  verifyIdTokenHint,
} from "../lib/oauth/tokens.js";

// OAuth 2.0 / OpenID Connect provider endpoints.
//
//   GET  /oauth/authorize    authorization code flow, PKCE (S256) mandatory
//   POST /oauth/token        authorization_code and refresh_token grants
//   GET  /oauth/userinfo     claims for a bearer access token
//   POST /oauth/introspect   RFC 7662, client-authenticated, live answer
//   POST /oauth/revoke       RFC 7009
//   GET  /oauth/logout       OIDC RP-initiated logout
//   POST /v1/authz/check     "may this user do X on Y?" decision API
//
// Only the browser-facing /authorize and /logout use the NovaForge session
// cookie; everything else is a back-channel call authenticated by the
// client's own credentials or by a bearer token, never by a cookie.

export const oauthRouter = Router();
export const v1Router = Router();

const authorizeLimit = rateLimit({ max: 120, windowMs: 60 * 1000 });
const tokenLimit = rateLimit({ max: 300, windowMs: 60 * 1000 });
// Failed client authentication is throttled harder, per IP + client.
const clientFailLimit = rateLimit({
  max: 60,
  windowMs: 5 * 60 * 1000,
  identity: (req) => (typeof req.body?.client_id === "string" ? req.body.client_id : (req.header("authorization") ?? "").slice(0, 80)),
});

function noStore(res: Response): void {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

/** Errors that must NOT redirect (unknown client / unregistered redirect_uri) are shown here. */
function errorPage(res: Response, status: number, message: string): void {
  noStore(res);
  res
    .status(status)
    .type("html")
    .send(
      `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Sign-in error</title>` +
        `<meta name="viewport" content="width=device-width,initial-scale=1">` +
        `<style>body{font-family:system-ui,sans-serif;background:#0b0f14;color:#e6edf3;display:grid;place-items:center;min-height:100vh;margin:0}` +
        `main{max-width:28rem;padding:2rem;border:1px solid #2b3440;border-radius:12px;background:#11161d}h1{font-size:1.1rem;margin:0 0 .5rem}p{color:#9aa7b4;margin:0}</style></head>` +
        `<body><main><h1>Sign-in could not continue</h1><p>${escapeHtml(message)}</p></main></body></html>`,
    );
}

function redirectWithParams(res: Response, base: string, params: Record<string, string | undefined>): void {
  const url = new URL(base);
  for (const [k, v] of Object.entries(params)) if (v !== undefined) url.searchParams.set(k, v);
  noStore(res);
  res.redirect(302, url.toString());
}

function oauthError(res: Response, status: number, error: string, description?: string): void {
  noStore(res);
  res.status(status).json({ error, ...(description ? { error_description: description } : {}) });
}

const B64URL_43 = /^[A-Za-z0-9_-]{43}$/;
const VERIFIER_FORMAT = /^[A-Za-z0-9\-._~]{43,128}$/;
const PRINTABLE = /^[\x21-\x7e]+$/; // printable ASCII, no whitespace

function singleString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

/** The NovaForge browser session behind the request's cookie, or null. */
async function currentSession(req: Request): Promise<{ userId: string; sessionId: string; authTime: Date } | null> {
  const token = req.cookies?.accessToken as string | undefined;
  if (!token) return null;
  let payload;
  try {
    payload = verifyAccessToken(token);
  } catch {
    return null;
  }
  if (!(await isSessionLive(payload.sessionId, payload.sub))) return null;
  const session = await prisma.session.findUnique({ where: { id: payload.sessionId }, select: { createdAt: true } });
  return session ? { userId: payload.sub, sessionId: payload.sessionId, authTime: session.createdAt } : null;
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

export function serveDiscovery(_req: Request, res: Response): void {
  res.setHeader("Cache-Control", "public, max-age=300");
  res.json(discoveryDocument());
}

// ---------------------------------------------------------------------------
// Authorization endpoint
// ---------------------------------------------------------------------------

oauthRouter.get("/authorize", authorizeLimit, async (req, res) => {
  // Every parameter must appear exactly once.
  const q = req.query;
  const get = (name: string) => singleString(q[name]);

  const clientId = get("client_id");
  const redirectUri = get("redirect_uri");
  const client =
    clientId && clientId.length <= 200 ? await prisma.oAuthClient.findUnique({ where: { clientId } }) : null;
  if (!client || client.status !== "ACTIVE") {
    errorPage(res, 400, "The application that sent you here is not recognised or is disabled.");
    return;
  }
  // Byte-exact match. No prefix, wildcard or normalisation; and on mismatch
  // the user is never redirected (open-redirect / code-theft defence).
  if (!redirectUri || !client.redirectUris.includes(redirectUri)) {
    errorPage(res, 400, "The redirect address in this request is not registered for the application.");
    return;
  }

  const state = get("state");
  const fail = (error: string, description?: string) =>
    redirectWithParams(res, redirectUri, { error, error_description: description, state, iss: issuer() });

  if (get("response_type") !== "code") return fail("unsupported_response_type");
  if (state === undefined || state.length < 1 || state.length > 512 || !PRINTABLE.test(state)) {
    return fail("invalid_request", "state is required (1-512 printable characters)");
  }
  const challenge = get("code_challenge");
  if (get("code_challenge_method") !== "S256" || !challenge || !B64URL_43.test(challenge)) {
    return fail("invalid_request", "PKCE with code_challenge_method=S256 is required");
  }
  const scopeParam = get("scope") ?? "";
  const scope = [...new Set(scopeParam.split(" ").filter(Boolean))];
  if (!scope.includes("openid")) return fail("invalid_scope", "the openid scope is required");
  if (scope.some((s) => !(SUPPORTED_SCOPES as readonly string[]).includes(s) || !client.allowedScopes.includes(s))) {
    return fail("invalid_scope", "one or more requested scopes are not allowed for this application");
  }
  const nonce = get("nonce");
  if (nonce === undefined || nonce.length < 1 || nonce.length > 512 || !PRINTABLE.test(nonce)) {
    return fail("invalid_request", "nonce is required (1-512 printable characters)");
  }
  const prompt = get("prompt");
  if (prompt !== undefined && prompt !== "none") return fail("invalid_request", "only prompt=none is supported");

  const session = await currentSession(req);
  if (!session) {
    if (prompt === "none") return fail("login_required");
    // Hand the browser to NovaForge's own sign-in page, which resumes this same request.
    // The destination is the configured NovaForge origin plus a fixed path, never a caller URL.
    const resume = new URL("/oauth/signin", env.rpOrigin);
    for (const [k, v] of Object.entries(q)) if (typeof v === "string") resume.searchParams.set(k, v);
    noStore(res);
    res.redirect(302, resume.toString());
    return;
  }

  const user = await prisma.user.findUnique({ where: { id: session.userId } });
  if (!user || user.status !== "ACTIVE") return fail("access_denied");
  const access = await loadAccess(client.id, user.id);
  if (client.requireAssignment && !hasAnyAccess(access)) {
    await auditedTransaction((tx) =>
      appendAuditLog(tx, {
        entityType: "OAuthClient",
        entityId: client.id,
        event: "OAUTH_ACCESS_DENIED",
        actorId: user.id,
        metadata: { clientId: client.clientId, reason: "no_role_in_application" },
      }),
    );
    return fail("access_denied", "you have not been granted access to this application");
  }

  const code = randomBytes(32).toString("base64url");
  await auditedTransaction(async (tx) => {
    const grant = await tx.oAuthGrant.create({
      data: { clientId: client.id, userId: user.id, sessionId: session.sessionId, scope: scope.join(" "), authTime: session.authTime },
    });
    await tx.authorizationCode.create({
      data: {
        codeHash: sha256Hex(code),
        clientId: client.id,
        grantId: grant.id,
        userId: user.id,
        redirectUri,
        scope: scope.join(" "),
        codeChallenge: challenge,
        nonce,
        authTime: session.authTime,
        expiresAt: new Date(Date.now() + AUTH_CODE_TTL_SEC * 1000),
      },
    });
    await appendAuditLog(tx, {
      entityType: "OAuthClient",
      entityId: client.id,
      event: "OAUTH_CODE_ISSUED",
      actorId: user.id,
      metadata: { clientId: client.clientId, grantId: grant.id, scope },
    });
  });
  redirectWithParams(res, redirectUri, { code, state, iss: issuer() });
});

// ---------------------------------------------------------------------------
// Token endpoint
// ---------------------------------------------------------------------------

function pkceMatches(verifier: string, challenge: string): boolean {
  const computed = Buffer.from(createHash("sha256").update(verifier).digest("base64url"));
  const expected = Buffer.from(challenge);
  return computed.length === expected.length && timingSafeEqual(computed, expected);
}

async function auditGrantEvent(client: OAuthClient, event: string, grantId: string, userId: string | null, extra: object = {}) {
  await auditedTransaction((tx) =>
    appendAuditLog(tx, {
      entityType: "OAuthClient",
      entityId: client.id,
      event,
      actorId: userId,
      metadata: { clientId: client.clientId, grantId, ...extra },
    }),
  );
}

oauthRouter.post("/token", tokenLimit, clientFailLimit, async (req, res) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  const auth = await authenticateClient(req, { allowPublic: true });
  if (!auth) {
    res.setHeader("WWW-Authenticate", 'Basic realm="oauth"');
    oauthError(res, 401, "invalid_client");
    return;
  }
  const { client } = auth;
  const grantType = singleString(body.grant_type);

  try {
    if (grantType === "authorization_code") {
      await handleCodeExchange(req, res, client);
    } else if (grantType === "refresh_token") {
      await handleRefresh(req, res, client);
    } else {
      oauthError(res, 400, "unsupported_grant_type");
    }
  } catch (err) {
    if (err instanceof IdentityKeysUnavailableError) {
      oauthError(res, 503, "temporarily_unavailable", "signing keys are not configured");
      return;
    }
    throw err;
  }
});

async function handleCodeExchange(req: Request, res: Response, client: OAuthClient): Promise<void> {
  const body = req.body as Record<string, unknown>;
  const code = singleString(body.code);
  const redirectUri = singleString(body.redirect_uri);
  const verifier = singleString(body.code_verifier);
  if (!code || code.length > 200 || !redirectUri || !verifier || !VERIFIER_FORMAT.test(verifier)) {
    oauthError(res, 400, "invalid_request");
    return;
  }

  const codeHash = sha256Hex(code);
  // Atomic single use: exactly one concurrent redemption can flip consumedAt.
  const consumed = await prisma.authorizationCode.updateMany({
    where: { codeHash, consumedAt: null, expiresAt: { gt: new Date() } },
    data: { consumedAt: new Date() },
  });
  const row = await prisma.authorizationCode.findUnique({ where: { codeHash } });
  if (consumed.count !== 1 || !row) {
    if (row?.consumedAt && row.clientId === client.id) {
      // Replay of an already-redeemed code: whatever it produced is now suspect (RFC 6749 4.1.2).
      const revoked = await prisma.$transaction((tx) => revokeGrant(tx, row.grantId, "authorization_code_replay"));
      if (revoked) await auditGrantEvent(client, "OAUTH_CODE_REPLAY_DETECTED", row.grantId, row.userId);
    }
    oauthError(res, 400, "invalid_grant");
    return;
  }
  if (row.clientId !== client.id || row.redirectUri !== redirectUri || !pkceMatches(verifier, row.codeChallenge)) {
    await auditGrantEvent(client, "OAUTH_CODE_EXCHANGE_REJECTED", row.grantId, row.userId, { reason: "binding_mismatch" });
    oauthError(res, 400, "invalid_grant");
    return;
  }

  const liveness = await liveGrantFor(row.grantId);
  if (!liveness.live) {
    oauthError(res, 400, "invalid_grant");
    return;
  }
  const scope = row.scope.split(" ");
  const tokens = await prisma.$transaction((tx) =>
    issueTokenSet(tx, {
      client,
      user: liveness.grant.user,
      grantId: row.grantId,
      scope,
      authTime: row.authTime,
      nonce: row.nonce,
      access: liveness.access,
      withRefreshToken: scope.includes("offline_access"),
    }),
  );
  await auditGrantEvent(client, "OAUTH_TOKENS_ISSUED", row.grantId, row.userId, { grant: "authorization_code" });
  noStore(res);
  res.json(tokens);
}

async function handleRefresh(req: Request, res: Response, client: OAuthClient): Promise<void> {
  const presented = singleString((req.body as Record<string, unknown>).refresh_token);
  if (!presented || !isWellFormedRefreshToken(presented)) {
    oauthError(res, 400, "invalid_grant");
    return;
  }
  const tokenHash = sha256Hex(presented);
  const row = await prisma.oAuthRefreshToken.findUnique({ where: { tokenHash }, include: { grant: true } });
  if (!row || row.grant.clientId !== client.id) {
    oauthError(res, 400, "invalid_grant");
    return;
  }
  if (row.usedAt) {
    // A rotated-out token is being replayed: assume the family is compromised.
    const revoked = await prisma.$transaction((tx) => revokeGrant(tx, row.grantId, "refresh_token_reuse"));
    if (revoked) await auditGrantEvent(client, "OAUTH_REFRESH_REUSE_DETECTED", row.grantId, row.grant.userId);
    oauthError(res, 400, "invalid_grant");
    return;
  }
  if (row.expiresAt <= new Date()) {
    oauthError(res, 400, "invalid_grant");
    return;
  }
  const liveness = await liveGrantFor(row.grantId);
  if (!liveness.live) {
    oauthError(res, 400, "invalid_grant");
    return;
  }

  const tokens = await prisma.$transaction(
    async (tx) => {
      // Atomic rotation: only one concurrent request can spend this token.
      const spent = await tx.oAuthRefreshToken.updateMany({ where: { id: row.id, usedAt: null }, data: { usedAt: new Date() } });
      if (spent.count !== 1) return null;
      const set = await issueTokenSet(tx, {
        client,
        user: liveness.grant.user,
        grantId: row.grantId,
        scope: row.grant.scope.split(" "),
        authTime: row.grant.authTime,
        nonce: null,
        access: liveness.access,
        withRefreshToken: true,
      });
      const next = await tx.oAuthRefreshToken.findUnique({ where: { tokenHash: sha256Hex(set.refresh_token!) } });
      await tx.oAuthRefreshToken.update({ where: { id: row.id }, data: { replacedById: next?.id } });
      return set;
    },
    { isolationLevel: Prisma.TransactionIsolationLevel.ReadCommitted },
  );
  if (!tokens) {
    const revoked = await prisma.$transaction((tx) => revokeGrant(tx, row.grantId, "refresh_token_reuse"));
    if (revoked) await auditGrantEvent(client, "OAUTH_REFRESH_REUSE_DETECTED", row.grantId, row.grant.userId, { concurrent: true });
    oauthError(res, 400, "invalid_grant");
    return;
  }
  noStore(res);
  res.json(tokens);
}

// ---------------------------------------------------------------------------
// UserInfo
// ---------------------------------------------------------------------------

function bearer(req: Request): string | null {
  const header = req.header("authorization");
  if (!header?.toLowerCase().startsWith("bearer ")) return null;
  const token = header.slice(7).trim();
  return token.length > 0 && token.length <= 8192 ? token : null;
}

async function userinfo(req: Request, res: Response): Promise<void> {
  const token = bearer(req);
  if (!token) {
    res.setHeader("WWW-Authenticate", "Bearer");
    oauthError(res, 401, "invalid_token");
    return;
  }
  let claims;
  try {
    claims = verifyAccessTokenJwt(token);
  } catch {
    res.setHeader("WWW-Authenticate", 'Bearer error="invalid_token"');
    oauthError(res, 401, "invalid_token");
    return;
  }
  const liveness = await liveGrantFor(claims.sid);
  if (!liveness.live || liveness.grant.userId !== claims.sub) {
    res.setHeader("WWW-Authenticate", 'Bearer error="invalid_token"');
    oauthError(res, 401, "invalid_token");
    return;
  }
  const scope = claims.scope.split(" ");
  noStore(res);
  res.json({
    sub: claims.sub,
    ...claimsForScope(liveness.grant.user, scope),
    ...(scope.includes("roles") ? { roles: liveness.access.roles, permissions: liveness.access.permissions } : {}),
  });
}
oauthRouter.get("/userinfo", tokenLimit, userinfo);
oauthRouter.post("/userinfo", tokenLimit, userinfo);

// ---------------------------------------------------------------------------
// Introspection (RFC 7662) and revocation (RFC 7009)
// ---------------------------------------------------------------------------

oauthRouter.post("/introspect", tokenLimit, clientFailLimit, async (req, res) => {
  const auth = await authenticateClient(req);
  if (!auth) {
    res.setHeader("WWW-Authenticate", 'Basic realm="oauth"');
    oauthError(res, 401, "invalid_client");
    return;
  }
  const { client } = auth;
  const token = singleString((req.body as Record<string, unknown>).token);
  noStore(res);
  if (!token || token.length > 8192) {
    res.json({ active: false });
    return;
  }

  // Refresh token?
  if (isWellFormedRefreshToken(token)) {
    const row = await prisma.oAuthRefreshToken.findUnique({ where: { tokenHash: sha256Hex(token) }, include: { grant: true } });
    if (!row || row.grant.clientId !== client.id || row.usedAt || row.expiresAt <= new Date()) {
      res.json({ active: false });
      return;
    }
    const liveness = await liveGrantFor(row.grantId);
    res.json(liveness.live ? { active: true, token_type: "refresh_token", client_id: client.clientId, sub: row.grant.userId, scope: row.grant.scope, exp: Math.floor(row.expiresAt.getTime() / 1000) } : { active: false });
    return;
  }

  let claims;
  try {
    claims = verifyAccessTokenJwt(token, client.audience);
  } catch {
    res.json({ active: false });
    return;
  }
  // Tenant isolation: a client can only learn about tokens issued to itself.
  if (claims.client_id !== client.clientId) {
    res.json({ active: false });
    return;
  }
  const liveness = await liveGrantFor(claims.sid);
  if (!liveness.live || liveness.grant.userId !== claims.sub || liveness.grant.clientId !== client.id) {
    res.json({ active: false });
    return;
  }
  const scope = claims.scope.split(" ");
  res.json({
    active: true,
    token_type: "Bearer",
    iss: issuer(),
    sub: claims.sub,
    aud: client.audience,
    client_id: client.clientId,
    scope: claims.scope,
    sid: claims.sid,
    jti: claims.jti,
    iat: claims.iat,
    exp: claims.exp,
    auth_time: claims.auth_time,
    // Live values, not the snapshot inside the token.
    roles: liveness.access.roles,
    permissions: liveness.access.permissions,
    ...claimsForScope(liveness.grant.user, scope),
    account_status: liveness.grant.user.status,
  });
});

oauthRouter.post("/revoke", tokenLimit, clientFailLimit, async (req, res) => {
  const auth = await authenticateClient(req);
  if (!auth) {
    res.setHeader("WWW-Authenticate", 'Basic realm="oauth"');
    oauthError(res, 401, "invalid_client");
    return;
  }
  const { client } = auth;
  const token = singleString((req.body as Record<string, unknown>).token);
  // RFC 7009: the response never reveals whether the token existed.
  if (token && token.length <= 8192) {
    let grantId: string | null = null;
    if (isWellFormedRefreshToken(token)) {
      const row = await prisma.oAuthRefreshToken.findUnique({ where: { tokenHash: sha256Hex(token) }, include: { grant: true } });
      if (row && row.grant.clientId === client.id) grantId = row.grantId;
    } else {
      try {
        const claims = verifyAccessTokenJwt(token);
        if (claims.client_id === client.clientId) grantId = claims.sid;
      } catch {
        /* not ours / invalid: nothing to revoke */
      }
    }
    if (grantId) {
      const id = grantId;
      const grant = await prisma.oAuthGrant.findUnique({ where: { id } });
      if (grant && grant.clientId === client.id) {
        // Revoking either token ends the whole grant: the application asked to stop using it.
        const revoked = await prisma.$transaction((tx) => revokeGrant(tx, id, "revoked_by_client"));
        if (revoked) await auditGrantEvent(client, "OAUTH_GRANT_REVOKED", id, grant.userId, { by: "client" });
      }
    }
  }
  noStore(res);
  res.status(200).json({});
});

// ---------------------------------------------------------------------------
// RP-initiated logout (OIDC RP-Initiated Logout 1.0)
// ---------------------------------------------------------------------------

oauthRouter.get("/logout", authorizeLimit, async (req, res) => {
  const idTokenHint = singleString(req.query.id_token_hint);
  const clientIdParam = singleString(req.query.client_id);
  const postLogout = singleString(req.query.post_logout_redirect_uri);
  const state = singleString(req.query.state);

  let hintClaims: { aud?: unknown; sid?: unknown; sub?: unknown } | null = null;
  if (idTokenHint) {
    try {
      hintClaims = verifyIdTokenHint(idTokenHint);
    } catch {
      errorPage(res, 400, "The logout request carried an invalid ID token.");
      return;
    }
  }
  const clientId = (typeof hintClaims?.aud === "string" ? hintClaims.aud : undefined) ?? clientIdParam;
  if (typeof hintClaims?.aud === "string" && clientIdParam && clientIdParam !== hintClaims.aud) {
    errorPage(res, 400, "The logout request is inconsistent.");
    return;
  }
  const client = clientId ? await prisma.oAuthClient.findUnique({ where: { clientId } }) : null;

  // Only ever redirect to a post-logout URI the client registered, byte-for-byte.
  let target: string | null = null;
  if (postLogout) {
    if (!client || !client.postLogoutRedirectUris.includes(postLogout)) {
      errorPage(res, 400, "The post-logout address is not registered for the application.");
      return;
    }
    target = postLogout;
  }

  // Sign out of NovaForge itself (single logout): ends this browser session, which
  // cascades to every application grant it produced. The session cookie is the proof of
  // identity -- an id_token_hint alone never ends someone else's session.
  const session = await currentSession(req);
  await auditedTransaction(async (tx) => {
    if (hintClaims && typeof hintClaims.sid === "string" && client) {
      const grant = await tx.oAuthGrant.findUnique({ where: { id: hintClaims.sid } });
      if (grant && grant.clientId === client.id && (!session || grant.userId === session.userId)) {
        if (await revokeGrant(tx, grant.id, "rp_initiated_logout")) {
          await appendAuditLog(tx, {
            entityType: "OAuthClient",
            entityId: client.id,
            event: "OAUTH_GRANT_REVOKED",
            actorId: grant.userId,
            metadata: { clientId: client.clientId, grantId: grant.id, by: "rp_initiated_logout" },
          });
        }
      }
    }
    if (session) {
      await tx.session.deleteMany({ where: { id: session.sessionId, userId: session.userId } });
      await appendAuditLog(tx, {
        entityType: "Session",
        entityId: session.sessionId,
        event: "SESSION_ENDED_BY_RP_LOGOUT",
        actorId: session.userId,
        metadata: { clientId: client?.clientId ?? null },
      });
    }
  });
  for (const name of ["accessToken", "refreshToken"]) res.clearCookie(name, { httpOnly: true, sameSite: "lax", secure: env.rpOrigin.startsWith("https") });
  noStore(res);
  if (target) {
    redirectWithParams(res, target, { state });
    return;
  }
  res.redirect(302, new URL("/login", env.rpOrigin).toString());
});

// ---------------------------------------------------------------------------
// Authorization decision API
// ---------------------------------------------------------------------------

// POST /api/v1/authz/check
//   Authorization: Basic <client_id:client_secret>   (the application's backend)
//   { "token": "<user's access token>", "permission": "jobs:decide", "resource": "corridor/NDLS-AGC" }
//   or { "token": ..., "checks": [ { "permission": ..., "resource": ... }, ... ] }
//
// The answer is computed from the database at the moment of the call, so it
// reflects an administrator's change immediately -- unlike the permission list
// inside the (cached) access token. Default-deny: anything unknown is `false`.
v1Router.post("/authz/check", tokenLimit, clientFailLimit, async (req, res) => {
  const auth = await authenticateClient(req);
  if (!auth) {
    res.setHeader("WWW-Authenticate", 'Basic realm="oauth"');
    oauthError(res, 401, "invalid_client");
    return;
  }
  const { client } = auth;
  const body = (req.body ?? {}) as Record<string, unknown>;
  const token = singleString(body.token);
  noStore(res);

  const checks: { permission: string; resource?: string }[] = [];
  if (Array.isArray(body.checks)) {
    if (body.checks.length === 0 || body.checks.length > 50) {
      res.status(400).json({ error: "invalid_request", error_description: "checks must contain 1-50 items" });
      return;
    }
    for (const item of body.checks) {
      const c = item as Record<string, unknown>;
      if (typeof c?.permission !== "string") {
        res.status(400).json({ error: "invalid_request", error_description: "every check needs a permission" });
        return;
      }
      checks.push({ permission: c.permission, resource: typeof c.resource === "string" ? c.resource : undefined });
    }
  } else if (typeof body.permission === "string") {
    checks.push({ permission: body.permission, resource: typeof body.resource === "string" ? body.resource : undefined });
  } else {
    res.status(400).json({ error: "invalid_request", error_description: "permission or checks is required" });
    return;
  }
  for (const c of checks) {
    if (!PERMISSION_KEY.test(c.permission) || (c.resource !== undefined && !isValidResource(c.resource))) {
      res.status(400).json({ error: "invalid_request", error_description: "malformed permission or resource" });
      return;
    }
  }

  const denyAll = (reason: string) =>
    res.json({ active: false, allowed: false, reason, decisions: checks.map((c) => ({ ...c, allowed: false })) });

  if (!token || token.length > 8192) return denyAll("invalid_token");
  let claims;
  try {
    claims = verifyAccessTokenJwt(token, client.audience);
  } catch {
    return denyAll("invalid_token");
  }
  if (claims.client_id !== client.clientId) return denyAll("invalid_token");
  const liveness = await liveGrantFor(claims.sid);
  if (!liveness.live || liveness.grant.userId !== claims.sub || liveness.grant.clientId !== client.id) {
    return denyAll("session_inactive");
  }
  const decisions = checks.map((c) => ({ ...c, allowed: isPermitted(liveness.access, c.permission, c.resource) }));
  res.json({
    active: true,
    sub: claims.sub,
    roles: liveness.access.roles,
    allowed: decisions.every((d) => d.allowed),
    decisions,
  });
});
