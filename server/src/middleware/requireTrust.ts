import type { NextFunction, Request, Response } from "express";
import { prisma } from "../lib/prisma.js";
import { decayedTrustLevel } from "../lib/trust.js";

// Trust decays 5 points per hour since a session's last re-verification
// (server/src/routes/auth.ts, POST /session/refresh) — a device that's been
// offline stays logged in with read access intact, but shouldn't be able to
// vote on or create sensitive actions until it re-proves itself. This is the
// piece of trust decay that was previously computed and exposed but never
// actually enforced anywhere.
//
// Gating is evaluated against the same effective (decayed) trust that
// identity assertions expose (server/src/lib/identityAssertion.ts), via the
// shared decayedTrustLevel() helper (server/src/lib/trust.ts) -- otherwise
// NovaForge would have two different notions of "current trust" live at
// once: a stale, undecayed one gating votes/actions and a decayed one handed
// to downstream services. This is a read-only evaluation: it never writes to
// the session row and never applies the refresh route's check-in recovery
// bonus, since merely being gated isn't a re-verification.
const MIN_TRUST_FOR_SENSITIVE_ACTIONS = 50;

export function requireTrust(minTrust: number = MIN_TRUST_FOR_SENSITIVE_ACTIONS) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const session = await prisma.session.findUnique({ where: { id: req.user!.sessionId } });
    if (!session) {
      res.status(401).json({ error: "Session not found" });
      return;
    }
    // Rounded the same way the refresh route rounds what it persists
    // (server/src/routes/auth.ts) and identity assertions round what they
    // assert, so the same session reports the same effective trust everywhere.
    const trustLevel = Math.round(decayedTrustLevel(session));
    if (trustLevel < minTrust) {
      res.status(403).json({
        error: "Session trust is too low for this action. Reconnect to re-verify, then try again.",
        trustLevel,
        required: minTrust,
      });
      return;
    }
    next();
  };
}
