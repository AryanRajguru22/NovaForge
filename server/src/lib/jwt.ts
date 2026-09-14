import jwt from "jsonwebtoken";
import { randomUUID } from "node:crypto";
import { env } from "./env.js";

export interface TokenPayload {
  sub: string; // user id
  sessionId: string;
}

export interface RefreshTokenPayload extends TokenPayload {
  jti: string;
}

const ACCESS_TOKEN_TTL = "15m";
const REFRESH_TOKEN_TTL = "30d";

// Embedded as an explicit payload claim -- not relied on merely via which
// secret happens to verify a token -- so an access token can never be
// accepted where a refresh token is expected, or vice versa, even in a
// hypothetical future misconfiguration where the two secrets ended up
// identical. This is defense-in-depth layered on top of the secrets already
// being separate (env.jwtAccessSecret / env.jwtRefreshSecret), not a
// replacement for it.
const ACCESS_TOKEN_TYPE = "access";
const REFRESH_TOKEN_TYPE = "refresh";

// Session tokens are NovaForge-internal: HS256 with secrets no other service
// ever holds, always re-validated against the Session row, and never
// accepted by a downstream service. They carry a fixed issuer and a
// NovaForge-only audience, and verification pins the algorithm, so they can't
// be confused with the ES256 identity assertions issued to relying services
// (server/src/lib/identityAssertion.ts), and vice versa.
const SESSION_TOKEN_ISSUER = "novaforge";
const SESSION_TOKEN_AUDIENCE = "novaforge:session";
const SESSION_VERIFY_OPTIONS: jwt.VerifyOptions = {
  algorithms: ["HS256"],
  issuer: SESSION_TOKEN_ISSUER,
  audience: SESSION_TOKEN_AUDIENCE,
};

export function signAccessToken(payload: TokenPayload): string {
  return jwt.sign({ ...payload, type: ACCESS_TOKEN_TYPE }, env.jwtAccessSecret, {
    algorithm: "HS256",
    expiresIn: ACCESS_TOKEN_TTL,
    issuer: SESSION_TOKEN_ISSUER,
    audience: SESSION_TOKEN_AUDIENCE,
  });
}

export function verifyAccessToken(token: string): TokenPayload {
  const decoded = jwt.verify(token, env.jwtAccessSecret, SESSION_VERIFY_OPTIONS) as jwt.JwtPayload;
  if (decoded.type !== ACCESS_TOKEN_TYPE) {
    throw new Error("Not an access token");
  }
  return { sub: decoded.sub as string, sessionId: decoded.sessionId as string };
}

// A fresh, cryptographically random identifier minted for every refresh
// token issued (at login) or rotated (server/src/lib/refreshRotation.ts).
// Never a secret itself -- its disclosure alone (e.g. from a database dump)
// proves nothing and forges nothing, since the token's authenticity is
// entirely carried by its JWT signature, which never touches the database.
// It exists purely so the database can name *which* refresh token is
// currently valid for a session, the same way Session.id itself is already
// a plaintext, database-visible identifier used only in combination with a
// valid JWT signature over it.
export function generateRefreshTokenId(): string {
  return randomUUID();
}

// jti is required, not optional-with-an-internal-default: every real caller
// (issuing a session at login, or rotating one) needs to know the exact jti
// used so it can also be the one written to Session.currentRefreshTokenId --
// an internally-generated jti the caller never sees would be useless for
// that and would silently reintroduce a token/database mismatch.
export function signRefreshToken(payload: TokenPayload, jti: string): string {
  return jwt.sign({ ...payload, type: REFRESH_TOKEN_TYPE }, env.jwtRefreshSecret, {
    algorithm: "HS256",
    expiresIn: REFRESH_TOKEN_TTL,
    jwtid: jti,
    issuer: SESSION_TOKEN_ISSUER,
    audience: SESSION_TOKEN_AUDIENCE,
  });
}

export function verifyRefreshToken(token: string): RefreshTokenPayload {
  const decoded = jwt.verify(token, env.jwtRefreshSecret, SESSION_VERIFY_OPTIONS) as jwt.JwtPayload;
  // A pre-P0-4 refresh token has no type/jti claim at all (both undefined)
  // and is rejected here unconditionally -- it must never be silently
  // treated as compatible with rotation. See the P0-4 report's "Legacy
  // Sessions" section for the full backward-compatibility handling.
  if (decoded.type !== REFRESH_TOKEN_TYPE || typeof decoded.jti !== "string" || decoded.jti.length === 0) {
    throw new Error("Not a valid refresh token");
  }
  return { sub: decoded.sub as string, sessionId: decoded.sessionId as string, jti: decoded.jti };
}
