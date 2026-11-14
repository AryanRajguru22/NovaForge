import jwt from "jsonwebtoken";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { OAuthClient, Prisma, User } from "@prisma/client";
import { prisma } from "../prisma.js";
import { sha256Hex } from "../canonicalJson.js";
import { getIdentityKeyRing, getVerificationKey } from "../identityKeys.js";
import { isSessionLive } from "../../middleware/requireAuth.js";
import {
  ACCESS_TOKEN_TYP,
  ACCESS_TOKEN_USE,
  ID_TOKEN_TTL_SEC,
  ID_TOKEN_TYP,
  ID_TOKEN_USE,
  issuer,
} from "./config.js";
import { hasAnyAccess, loadAccess, type AccessContext } from "./rbac.js";

// Token model
//   access_token   ES256 JWT, typ "at+jwt" (RFC 9068), token_use "access_token".
//                  aud = the application's audience. Short-lived (per client).
//                  Carries roles/permissions as a convenience snapshot; the
//                  authoritative, live answer is introspection / authz check.
//   id_token       ES256 JWT, typ "JWT", token_use "id_token", aud = client_id,
//                  carries nonce. 5 minutes. Proves authentication to the RP.
//   refresh_token  Opaque, single-use, rotating, stored hashed.
// The three have distinct typ/token_use values and every verifier checks them,
// so none can be presented where another is expected, and none can be
// confused with the legacy identity assertion (typ "nf-identity+jwt") or with
// NovaForge's own HS256 session cookies.

export interface TokenSet {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  scope: string;
  id_token?: string;
  refresh_token?: string;
}

function s256(value: string): string {
  return createHash("sha256").update(value).digest("base64url");
}

/** at_hash / c_hash: left half of SHA-256, base64url (OIDC Core 3.1.3.6). */
export function halfHash(value: string): string {
  return createHash("sha256").update(value).digest().subarray(0, 16).toString("base64url");
}

export function claimsForScope(user: Pick<User, "name" | "email">, scope: string[]) {
  return {
    ...(scope.includes("profile") ? { name: user.name } : {}),
    ...(scope.includes("email") ? { email: user.email, email_verified: false } : {}),
  };
}

export function signAccessToken(input: {
  client: Pick<OAuthClient, "clientId" | "audience" | "accessTokenTtlSec">;
  user: Pick<User, "id">;
  grantId: string;
  scope: string[];
  authTime: Date;
  access: AccessContext;
}): { token: string; jti: string; expiresIn: number } {
  const { current } = getIdentityKeyRing();
  const jti = randomUUID();
  const expiresIn = input.client.accessTokenTtlSec;
  const token = jwt.sign(
    {
      token_use: ACCESS_TOKEN_USE,
      client_id: input.client.clientId,
      scope: input.scope.join(" "),
      sid: input.grantId,
      auth_time: Math.floor(input.authTime.getTime() / 1000),
      roles: input.access.roles,
      permissions: input.access.permissions,
    },
    current.privateKey,
    {
      algorithm: "ES256",
      header: { alg: "ES256", typ: ACCESS_TOKEN_TYP, kid: current.kid },
      issuer: issuer(),
      audience: input.client.audience,
      subject: input.user.id,
      jwtid: jti,
      expiresIn,
    },
  );
  return { token, jti, expiresIn };
}

export function signIdToken(input: {
  client: Pick<OAuthClient, "clientId">;
  user: Pick<User, "id" | "name" | "email">;
  grantId: string;
  scope: string[];
  authTime: Date;
  nonce?: string | null;
  accessToken: string;
  access: AccessContext;
}): string {
  const { current } = getIdentityKeyRing();
  return jwt.sign(
    {
      token_use: ID_TOKEN_USE,
      principal_type: "user",
      account_status: "ACTIVE",
      sid: input.grantId,
      auth_time: Math.floor(input.authTime.getTime() / 1000),
      at_hash: halfHash(input.accessToken),
      ...(input.nonce ? { nonce: input.nonce } : {}),
      ...claimsForScope(input.user, input.scope),
      ...(input.scope.includes("roles") ? { roles: input.access.roles, permissions: input.access.permissions } : {}),
    },
    current.privateKey,
    {
      algorithm: "ES256",
      header: { alg: "ES256", typ: ID_TOKEN_TYP, kid: current.kid },
      issuer: issuer(),
      audience: input.client.clientId,
      subject: input.user.id,
      jwtid: randomUUID(),
      expiresIn: ID_TOKEN_TTL_SEC,
    },
  );
}

export interface AccessTokenClaims extends jwt.JwtPayload {
  sub: string;
  client_id: string;
  sid: string;
  scope: string;
  roles: string[];
  permissions: string[];
}

/**
 * Verifies an access token's signature, algorithm, header type, issuer,
 * expiry and token_use. Does NOT check liveness (grant, session, user):
 * callers that act on the token must also call `liveGrantFor`.
 */
export function verifyAccessTokenJwt(token: string, expectedAudience?: string): AccessTokenClaims {
  const decoded = jwt.decode(token, { complete: true });
  if (!decoded || typeof decoded.payload === "string") throw new Error("malformed");
  const header = decoded.header;
  if (header.alg !== "ES256" || header.typ !== ACCESS_TOKEN_TYP || typeof header.kid !== "string") {
    throw new Error("wrong token type");
  }
  const key = getVerificationKey(header.kid);
  if (!key) throw new Error("unknown key");
  const claims = jwt.verify(token, key, {
    algorithms: ["ES256"],
    issuer: issuer(),
    ...(expectedAudience ? { audience: expectedAudience } : {}),
  }) as AccessTokenClaims;
  if (claims.token_use !== ACCESS_TOKEN_USE) throw new Error("wrong token use");
  if (typeof claims.sub !== "string" || typeof claims.sid !== "string" || typeof claims.client_id !== "string") {
    throw new Error("missing claims");
  }
  return claims;
}

/** Verifies an ID token the provider issued (used for id_token_hint at logout; expiry is ignored). */
export function verifyIdTokenHint(token: string): jwt.JwtPayload {
  const decoded = jwt.decode(token, { complete: true });
  if (!decoded || typeof decoded.payload === "string") throw new Error("malformed");
  const header = decoded.header;
  if (header.alg !== "ES256" || header.typ !== ID_TOKEN_TYP || typeof header.kid !== "string") throw new Error("wrong type");
  const key = getVerificationKey(header.kid);
  if (!key) throw new Error("unknown key");
  const claims = jwt.verify(token, key, { algorithms: ["ES256"], issuer: issuer(), ignoreExpiration: true }) as jwt.JwtPayload;
  if (claims.token_use !== ID_TOKEN_USE) throw new Error("wrong token use");
  return claims;
}

// --- Refresh tokens -------------------------------------------------------

const REFRESH_FORMAT = /^nfrt_[A-Za-z0-9_-]{43}$/;

export function isWellFormedRefreshToken(value: string): boolean {
  return REFRESH_FORMAT.test(value);
}

export async function createRefreshToken(
  tx: Prisma.TransactionClient,
  grantId: string,
  ttlSec: number,
): Promise<{ token: string; id: string }> {
  const token = `nfrt_${randomBytes(32).toString("base64url")}`;
  const row = await tx.oAuthRefreshToken.create({
    data: { grantId, tokenHash: sha256Hex(token), expiresAt: new Date(Date.now() + ttlSec * 1000) },
  });
  return { token, id: row.id };
}

// --- Liveness -------------------------------------------------------------

export type GrantLiveness =
  | { live: true; grant: NonNullable<Awaited<ReturnType<typeof loadGrant>>>; access: AccessContext }
  | { live: false; reason: "grant_revoked" | "session_ended" | "user_inactive" | "client_inactive" | "access_removed" | "unknown_grant" };

async function loadGrant(grantId: string) {
  return prisma.oAuthGrant.findUnique({ where: { id: grantId }, include: { client: true, user: true } });
}

/**
 * Whether a grant may still be used right now: not revoked, its NovaForge
 * session still live, its user ACTIVE, its application ACTIVE, and (for
 * default-deny applications) the user still holding at least one role there.
 * Every failure mode is distinguishable internally but should be reported to
 * callers as a plain `invalid_grant` / `active:false`.
 */
export async function liveGrantFor(grantId: string): Promise<GrantLiveness> {
  const grant = await loadGrant(grantId);
  if (!grant) return { live: false, reason: "unknown_grant" };
  if (grant.revokedAt) return { live: false, reason: "grant_revoked" };
  if (grant.client.status !== "ACTIVE") return { live: false, reason: "client_inactive" };
  if (grant.user.status !== "ACTIVE") return { live: false, reason: "user_inactive" };
  if (!(await isSessionLive(grant.sessionId, grant.userId))) return { live: false, reason: "session_ended" };
  const access = await loadAccess(grant.clientId, grant.userId);
  if (grant.client.requireAssignment && !hasAnyAccess(access)) return { live: false, reason: "access_removed" };
  return { live: true, grant, access };
}

export async function revokeGrant(tx: Prisma.TransactionClient, grantId: string, reason: string): Promise<boolean> {
  const result = await tx.oAuthGrant.updateMany({ where: { id: grantId, revokedAt: null }, data: { revokedAt: new Date(), revokedReason: reason } });
  return result.count === 1;
}

/** Mints the response of the token endpoint for a live grant. */
export async function issueTokenSet(
  tx: Prisma.TransactionClient,
  input: {
    client: OAuthClient;
    user: Pick<User, "id" | "name" | "email">;
    grantId: string;
    scope: string[];
    authTime: Date;
    nonce?: string | null;
    access: AccessContext;
    withRefreshToken: boolean;
  },
): Promise<TokenSet> {
  const at = signAccessToken({ ...input, grantId: input.grantId });
  const response: TokenSet = {
    access_token: at.token,
    token_type: "Bearer",
    expires_in: at.expiresIn,
    scope: input.scope.join(" "),
  };
  if (input.scope.includes("openid")) {
    response.id_token = signIdToken({ ...input, accessToken: at.token });
  }
  if (input.withRefreshToken) {
    response.refresh_token = (await createRefreshToken(tx, input.grantId, input.client.refreshTokenTtlSec)).token;
  }
  await tx.oAuthGrant.update({ where: { id: input.grantId }, data: { lastUsedAt: new Date() } });
  return response;
}

export { s256 };
