import jwt from "jsonwebtoken";
import { createPublicKey, type JsonWebKey, type KeyObject } from "node:crypto";

// Reference verifier for NovaForge identity assertions, written the way a
// downstream relying service (e.g. Pashupatastra) must verify them. It has
// no access to NovaForge's database, environment or private keys -- only the
// published public JWKS -- which is exactly why it cannot mint identities.
//
// It is deliberately strict:
//   * alg must be ES256 (rejects "none", HS256 key-confusion, RS*, etc.)
//   * kid must name a key in the trusted JWKS
//   * iss and aud must match exactly; exp, iat, sub, sid, jti are required
//   * token_use must be "identity_assertion"
//   * lifetime (exp - iat) may not exceed maxLifetimeSec
//
// A valid assertion proves "NovaForge authenticated this principal and issued
// this statement for this audience". Freshness beyond exp (e.g. whether the
// session was revoked a minute ago) requires NovaForge's introspection
// endpoint. Authorization decisions remain the relying service's own.

export const IDENTITY_ASSERTION_TOKEN_USE = "identity_assertion";
export const IDENTITY_ASSERTION_TYP = "nf-identity+jwt";

export interface IdentityAssertionClaims {
  iss: string;
  aud: string;
  sub: string;
  sid: string;
  jti: string;
  iat: number;
  nbf?: number;
  exp: number;
  token_use: typeof IDENTITY_ASSERTION_TOKEN_USE;
  principal_type: "user";
  role: string;
  account_status: "ACTIVE";
  auth_time: number;
  trust_level: number;
}

export class IdentityAssertionError extends Error {}

export interface IdentityAssertionVerifierOptions {
  issuer: string;
  audience: string;
  jwks: { keys: (JsonWebKey & { kid?: string })[] };
  clockToleranceSec?: number;
  maxLifetimeSec?: number;
  now?: () => number;
}

export function createIdentityAssertionVerifier(opts: IdentityAssertionVerifierOptions) {
  const keys = new Map<string, KeyObject>();
  for (const jwk of opts.jwks.keys) {
    if (!jwk.kid || jwk.kty !== "EC" || jwk.crv !== "P-256") continue;
    keys.set(jwk.kid, createPublicKey({ key: jwk, format: "jwk" }));
  }
  const clockToleranceSec = opts.clockToleranceSec ?? 30;
  const maxLifetimeSec = opts.maxLifetimeSec ?? 600;

  return function verify(token: string): IdentityAssertionClaims {
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || typeof decoded.payload === "string") throw new IdentityAssertionError("Malformed assertion");
    if (decoded.header.alg !== "ES256") throw new IdentityAssertionError("Unsupported algorithm");
    if (decoded.header.typ !== IDENTITY_ASSERTION_TYP) throw new IdentityAssertionError("Unexpected token type");
    const kid = decoded.header.kid;
    const key = kid ? keys.get(kid) : undefined;
    if (!key) throw new IdentityAssertionError("Unknown signing key");

    let claims: jwt.JwtPayload;
    try {
      claims = jwt.verify(token, key, {
        algorithms: ["ES256"],
        issuer: opts.issuer,
        audience: opts.audience,
        clockTolerance: clockToleranceSec,
        clockTimestamp: opts.now ? Math.floor(opts.now() / 1000) : undefined,
      }) as jwt.JwtPayload;
    } catch (err) {
      throw new IdentityAssertionError(`Assertion rejected: ${(err as Error).message}`);
    }

    if (claims.aud !== opts.audience) throw new IdentityAssertionError("Audience must be a single exact value");
    if (claims.token_use !== IDENTITY_ASSERTION_TOKEN_USE) throw new IdentityAssertionError("Not an identity assertion");
    for (const field of ["sub", "sid", "jti", "role"] as const) {
      if (typeof claims[field] !== "string" || claims[field].length === 0) {
        throw new IdentityAssertionError(`Missing ${field}`);
      }
    }
    if (typeof claims.exp !== "number" || typeof claims.iat !== "number") throw new IdentityAssertionError("Missing exp/iat");
    if (claims.exp - claims.iat > maxLifetimeSec) throw new IdentityAssertionError("Assertion lifetime too long");
    const nowSec = Math.floor((opts.now ? opts.now() : Date.now()) / 1000);
    if (claims.iat > nowSec + clockToleranceSec) throw new IdentityAssertionError("Assertion issued in the future");
    if (claims.principal_type !== "user" || claims.account_status !== "ACTIVE") {
      throw new IdentityAssertionError("Principal is not an active user");
    }
    return claims as IdentityAssertionClaims;
  };
}
