import { Router } from "express";
import { z } from "zod";
import { prisma } from "../lib/prisma.js";
import { verifyAccessToken } from "../lib/jwt.js";
import { isSessionLive } from "../middleware/requireAuth.js";
import { requireService } from "../lib/serviceAuth.js";
import { issueIdentityAssertion, verifyIssuedIdentityAssertion } from "../lib/identityAssertion.js";
import { IdentityKeysUnavailableError } from "../lib/identityKeys.js";
import { rateLimit } from "../middleware/rateLimit.js";

// Service-to-service API. Every route requires a service credential with the
// right scope; no user session or cookie is ever accepted here. Intended to
// be reachable only from the private network in a real deployment.
//
// Trust flow for a relying service (not integrated yet):
//   user -> NovaForge session (httpOnly cookie)
//   relying service backend -> POST /internal/identity-assertions with its
//     own service credential + the user's NovaForge access token
//   NovaForge verifies the session is live and the user ACTIVE, then returns
//     a short-lived ES256 assertion whose aud is the *authenticated service's*
//     audience (never caller-chosen)
//   relying service verifies the assertion offline with the public JWKS,
//     optionally re-checks freshness via /internal/introspect, and builds its
//     own actor context and authorization decisions from it.

export const internalRouter = Router();

const internalLimit = rateLimit({ max: 600, windowMs: 60 * 1000 });

const assertionRequestSchema = z.object({ accessToken: z.string().min(1).max(4096) });

internalRouter.post("/identity-assertions", internalLimit, requireService("identity:assert"), async (req, res) => {
  const parsed = assertionRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "accessToken is required" });
    return;
  }

  let payload;
  try {
    payload = verifyAccessToken(parsed.data.accessToken);
  } catch {
    res.status(401).json({ error: "User session is not valid" });
    return;
  }
  if (!(await isSessionLive(payload.sessionId, payload.sub))) {
    res.status(401).json({ error: "User session is not valid" });
    return;
  }
  const session = await prisma.session.findUnique({ where: { id: payload.sessionId }, include: { user: true } });
  if (!session || session.user.status !== "ACTIVE") {
    res.status(401).json({ error: "User session is not valid" });
    return;
  }

  try {
    const issued = issueIdentityAssertion({ audience: req.service!.audience, user: session.user, session });
    res.json({ assertion: issued.assertion, expiresAt: issued.expiresAt, tokenType: "nf-identity+jwt" });
  } catch (err) {
    if (err instanceof IdentityKeysUnavailableError) {
      res.status(503).json({ error: "Identity assertions are not configured" });
      return;
    }
    throw err;
  }
});

const introspectSchema = z.object({ assertion: z.string().min(1).max(8192) });

// Freshness check for an assertion this service holds: still correctly
// signed, addressed to this service, unexpired, its session still live and
// its user still ACTIVE. Inactive results carry no reason, so the endpoint is
// not an oracle for why a token failed.
internalRouter.post("/introspect", internalLimit, requireService("identity:introspect"), async (req, res) => {
  const parsed = introspectSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "assertion is required" });
    return;
  }

  let claims;
  try {
    claims = verifyIssuedIdentityAssertion(parsed.data.assertion, req.service!.audience);
  } catch {
    res.json({ active: false });
    return;
  }
  if (!(await isSessionLive(claims.sid, claims.sub))) {
    res.json({ active: false });
    return;
  }
  const user = await prisma.user.findUnique({ where: { id: claims.sub }, select: { role: true, status: true } });
  if (!user || user.status !== "ACTIVE") {
    res.json({ active: false });
    return;
  }
  res.json({
    active: true,
    sub: claims.sub,
    sid: claims.sid,
    aud: claims.aud,
    exp: claims.exp,
    role: user.role,
    accountStatus: user.status,
  });
});
