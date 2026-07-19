import type { NextFunction, Request, Response } from "express";
import { prisma } from "../lib/prisma.js";

// Trust decays 5 points per hour since a session's last re-verification
// (server/src/routes/auth.ts, POST /session/refresh) — a device that's been
// offline stays logged in with read access intact, but shouldn't be able to
// vote on or create sensitive actions until it re-proves itself. This is the
// piece of trust decay that was previously computed and exposed but never
// actually enforced anywhere.
const MIN_TRUST_FOR_SENSITIVE_ACTIONS = 50;

export function requireTrust(minTrust: number = MIN_TRUST_FOR_SENSITIVE_ACTIONS) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const session = await prisma.session.findUnique({ where: { id: req.user!.sessionId } });
    if (!session) {
      res.status(401).json({ error: "Session not found" });
      return;
    }
    if (session.trustLevel < minTrust) {
      res.status(403).json({
        error: "Session trust is too low for this action. Reconnect to re-verify, then try again.",
        trustLevel: session.trustLevel,
        required: minTrust,
      });
      return;
    }
    next();
  };
}
