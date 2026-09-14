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

// A cryptographically valid access token isn't enough on its own: revoking a
// session (DELETE /auth/sessions/:id) only ever deleted the Session row, and
// this check used to stop at "is the JWT signature/exp valid" without ever
// looking the session back up. That's why revoking a device from another one
// didn't take effect there until its access token happened to expire
// naturally (up to 15 minutes) -- the revoked device's existing token kept
// passing this check the whole time. Every request now confirms the session
// it names still actually exists (and hasn't hit its own expiresAt), so a
// revoke is authoritative on the very next request from that device, not
// just eventually.
//
// Extracted so server/src/lib/socketSecurity.ts can reuse the exact same
// authoritative check for Socket.io's handshake and join-time
// re-validation, instead of maintaining a second, potentially-drifting copy
// of "does this session still exist and hasn't expired".
//
// A session is only live while its user is ACTIVE. Disabling or suspending
// an account also deletes its sessions (server/src/routes/users.ts), but this
// check is what makes the status authoritative on its own -- for REST, the
// Socket.io handshake/join checks, and the revocation sweep alike.
export async function isSessionLive(sessionId: string, expectedUserId?: string): Promise<boolean> {
  const session = await prisma.session.findUnique({
    where: { id: sessionId },
    include: { user: { select: { id: true, status: true } } },
  });
  if (!session || session.expiresAt < new Date()) return false;
  if (session.user.status !== "ACTIVE") return false;
  if (expectedUserId !== undefined && session.userId !== expectedUserId) return false;
  return true;
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

  if (!(await isSessionLive(payload.sessionId, payload.sub))) {
    res.status(401).json({ error: "Session has been revoked or expired" });
    return;
  }

  req.user = { id: payload.sub, sessionId: payload.sessionId };
  next();
}
