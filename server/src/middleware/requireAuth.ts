import type { NextFunction, Request, Response } from "express";
import { verifyAccessToken } from "../lib/jwt.js";
import { prisma } from "../lib/prisma.js";

export interface AuthenticatedUser {
  id: string;
  sessionId: string;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: AuthenticatedUser;
    }
  }
}

export async function requireAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  const token = req.cookies?.accessToken as string | undefined;
  if (!token) {
    res.status(401).json({ error: "Not authenticated" });
    return;
  }
  let payload;
  try {
    payload = verifyAccessToken(token);
  } catch {
    res.status(401).json({ error: "Invalid or expired session" });
    return;
  }

  // A cryptographically valid access token isn't enough on its own: revoking
  // a session (DELETE /auth/sessions/:id) only ever deleted the Session row,
  // and this check used to stop at "is the JWT signature/exp valid" without
  // ever looking the session back up. That's why revoking a device from
  // another one didn't take effect there until its access token happened to
  // expire naturally (up to 15 minutes) -- the revoked device's existing
  // token kept passing this check the whole time. Every request now confirms
  // the session it names still actually exists (and hasn't hit its own
  // expiresAt), so a revoke is authoritative on the very next request from
  // that device, not just eventually.
  const session = await prisma.session.findUnique({ where: { id: payload.sessionId } });
  if (!session || session.expiresAt < new Date()) {
    res.status(401).json({ error: "Session has been revoked or expired" });
    return;
  }

  req.user = { id: payload.sub, sessionId: payload.sessionId };
  next();
}
