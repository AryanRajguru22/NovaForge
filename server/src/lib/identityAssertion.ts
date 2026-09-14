import jwt from "jsonwebtoken";
import { randomUUID } from "node:crypto";
import { env } from "./env.js";
import { getIdentityKeyRing, getPublicJwks } from "./identityKeys.js";
import { decayedTrustLevel } from "./trust.js";
import {
  createIdentityAssertionVerifier,
  IDENTITY_ASSERTION_TOKEN_USE,
  IDENTITY_ASSERTION_TYP,
  type IdentityAssertionClaims,
} from "./identityAssertionVerifier.js";

export const IDENTITY_ASSERTION_TTL_SEC = 300;

export function identityIssuer(): string {
  return process.env.IDENTITY_ISSUER ?? env.rpOrigin;
}

export function issueIdentityAssertion(input: {
  audience: string;
  user: { id: string; role: string; status: string };
  session: { id: string; createdAt: Date; trustLevel: number; lastVerifiedAt: Date };
}): { assertion: string; expiresAt: Date; jti: string } {
  if (input.user.status !== "ACTIVE") throw new Error("Refusing to assert identity for an inactive user");
  // The stored trustLevel is only rewritten when the session checks in, so a
  // downstream service must receive the trust in effect *now*, not the value
  // as of the last refresh. Rounded to an integer exactly as the refresh route
  // rounds what it persists. Computed only -- the session row is deliberately
  // not updated here.
  const trustLevel = Math.round(decayedTrustLevel(input.session));
  const { current } = getIdentityKeyRing();
  const jti = randomUUID();
  const claims = {
    token_use: IDENTITY_ASSERTION_TOKEN_USE,
    principal_type: "user",
    sid: input.session.id,
    role: input.user.role,
    account_status: "ACTIVE",
    auth_time: Math.floor(input.session.createdAt.getTime() / 1000),
    trust_level: trustLevel,
  };
  const assertion = jwt.sign(claims, current.privateKey, {
    algorithm: "ES256",
    keyid: current.kid,
    header: { alg: "ES256", typ: IDENTITY_ASSERTION_TYP, kid: current.kid },
    issuer: identityIssuer(),
    audience: input.audience,
    subject: input.user.id,
    jwtid: jti,
    expiresIn: IDENTITY_ASSERTION_TTL_SEC,
  });
  return { assertion, expiresAt: new Date(Date.now() + IDENTITY_ASSERTION_TTL_SEC * 1000), jti };
}

/** Verifies an assertion NovaForge issued, using only its own public JWKS. */
export function verifyIssuedIdentityAssertion(token: string, audience: string): IdentityAssertionClaims {
  return createIdentityAssertionVerifier({ issuer: identityIssuer(), audience, jwks: getPublicJwks() })(token);
}
