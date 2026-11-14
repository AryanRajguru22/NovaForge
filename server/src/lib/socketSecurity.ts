import type { Server, Socket } from "socket.io";
import { z } from "zod";
import type { Role } from "@prisma/client";
import { prisma } from "./prisma.js";
import { verifyAccessToken } from "./jwt.js";
import { isSessionLive } from "../middleware/requireAuth.js";
import { canViewApprovalRecord } from "./approvalAccess.js";
import { effectiveLevel } from "./policySnapshot.js";

// Socket.io's own room-membership mechanism is not, and must never be
// treated as, an authorization boundary: a room is just a string key, and
// the room names this app uses are ApprovalRequest ids -- if joining a room
// required nothing but knowing that id, the id itself would function as a
// bearer credential for that request's live vote-cast/status-update stream.
// This module is the fix: it authenticates the socket itself (who is this,
// via the same httpOnly session cookie REST already trusts) before any
// "connection" handler runs, and separately authorizes each room join (does
// this specific, authenticated user have any legitimate relationship to
// this specific request) before ever calling socket.join(). Established
// security boundary:
//
//   cookie -> JWT -> live Session -> authenticated socket
//     -> fresh request/policy lookup -> requester OR eligible role -> room
//
// Nothing here changes who can cast a vote or how -- REST remains the sole
// authoritative mutation path (server/src/routes/approvals.ts). This only
// gates who is allowed to *hear about* a request's live activity.

declare module "socket.io" {
  interface SocketData {
    // Handshake-time snapshot only. userId/sessionId are stable for the
    // life of the connection (a session doesn't get reassigned to a
    // different user mid-connection). role is deliberately NOT trusted for
    // authorization decisions made after the handshake -- see the join
    // handler below, which always re-reads the live User row instead. It's
    // still attached because a cheap, approximate value is useful for
    // logging/debugging, just never for deciding access.
    userId: string;
    sessionId: string;
    role: Role;
  }
}

type JoinAck = { ok: true } | { ok: false; error: string };

const DENIED: JoinAck = { ok: false, error: "Not authorized" };

const requestIdSchema = z.string().uuid();

// Zod already covers "missing" (fails z.string()), "non-string" (same),
// "empty string" and "absurdly large strings" (both fail the fixed-length
// UUID format) -- no separate length/type checks needed on top of it, and
// no new validation dependency: zod is already used throughout this
// codebase for exactly this kind of input shape check.

const DEFAULT_SWEEP_INTERVAL_MS = 60_000;

let sweepHandle: NodeJS.Timeout | null = null;

/** Reads the accessToken cookie's raw value out of a Socket.io handshake's
 * Cookie header, without adding a cookie-parsing dependency -- the browser
 * already sends this header automatically (the client connects with
 * withCredentials: true, and the Socket.io server's CORS config already has
 * credentials: true), it's just never been read on the server before now.
 * Deliberately tolerant of a missing/malformed header: any failure to find
 * a value here simply falls through to "unauthenticated", never a thrown
 * error. */
function extractAccessTokenCookie(cookieHeader: string | undefined): string | undefined {
  if (!cookieHeader) return undefined;
  for (const part of cookieHeader.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim();
    if (key !== "accessToken") continue;
    const rawValue = part.slice(eq + 1).trim();
    try {
      return decodeURIComponent(rawValue);
    } catch {
      return rawValue;
    }
  }
  return undefined;
}

/**
 * Wires up Socket.io authentication (io.use), the authorized join-challenge
 * handler, and a periodic connected-socket revocation sweep. Mirrors
 * initEscalationService/stopEscalationService's lifecycle pattern
 * (server/src/lib/escalation.ts) so tests can start/stop this deterministically
 * instead of it running as an import-time side effect.
 */
export function initSocketSecurity(io: Server, options: { sweepIntervalMs?: number } = {}): void {
  io.use(async (socket, next) => {
    try {
      const token = extractAccessTokenCookie(socket.handshake.headers.cookie);
      if (!token) {
        next(new Error("Authentication required"));
        return;
      }

      let payload;
      try {
        payload = verifyAccessToken(token);
      } catch {
        next(new Error("Authentication required"));
        return;
      }

      // JWT validity alone is never sufficient -- the same principle
      // requireAuth already enforces for every REST request (see the
      // comment on isSessionLive, server/src/middleware/requireAuth.ts).
      if (!(await isSessionLive(payload.sessionId, payload.sub))) {
        next(new Error("Authentication required"));
        return;
      }

      const user = await prisma.user.findUnique({ where: { id: payload.sub } });
      if (!user) {
        next(new Error("Authentication required"));
        return;
      }

      socket.data.userId = user.id;
      socket.data.sessionId = payload.sessionId;
      socket.data.role = user.role;
      next();
    } catch (err) {
      // A genuine unexpected failure (e.g. a database error) must not be
      // misreported as "you're not authenticated" in the logs -- it's
      // logged distinctly here even though the client-facing rejection
      // stays exactly as generic as an ordinary auth failure, so an
      // unauthenticated client never learns whether it hit a real 401-style
      // rejection or an internal error.
      console.error("[socket auth] unexpected error during handshake authentication", err);
      next(new Error("Authentication required"));
    }
  });

  io.on("connection", (socket: Socket) => {
    socket.on("join-challenge", async (rawRequestId: unknown, ack?: (result: JoinAck) => void) => {
      const respond = (result: JoinAck) => {
        if (typeof ack === "function") ack(result);
      };

      try {
        const parsed = requestIdSchema.safeParse(rawRequestId);
        if (!parsed.success) {
          respond(DENIED);
          return;
        }
        const requestId = parsed.data;

        // Re-check session liveness on every join, not just once at
        // handshake time -- a socket can stay connected far longer than a
        // 15-minute access token or the session behind it might remain
        // valid. If it's already dead, there's no reason to leave this
        // socket sitting connected until the periodic sweep (below) gets
        // to it -- close it immediately since we've just proven it.
        if (!(await isSessionLive(socket.data.sessionId))) {
          respond(DENIED);
          socket.disconnect(true);
          return;
        }

        const approvalRequest = await prisma.approvalRequest.findUnique({
          where: { id: requestId },
          include: { action: true, policyLevels: true, votes: { select: { approverId: true } } },
        });
        if (!approvalRequest) {
          // A nonexistent id is denied identically to an existing-but-
          // unauthorized one -- no room is ever created/joined for it, and
          // the client learns nothing about whether the id was real.
          respond(DENIED);
          return;
        }

        // Authorization always reads live data, never the handshake-time
        // socket.data.role snapshot: a role change or a policy edit must
        // take effect on the very next join attempt, not just the next
        // reconnect.
        const user = await prisma.user.findUnique({ where: { id: socket.data.userId } });
        if (!user) {
          respond(DENIED);
          return;
        }

        // Same rule as REST's GET /actions/:id (server/src/lib/approvalAccess.ts),
        // so live events never reveal more than the detail endpoint would.
        const allowed = canViewApprovalRecord({
          userId: user.id,
          role: user.role,
          action: approvalRequest.action,
          // The frozen level in force, not the live policy (null => only
          // requester / voters / SUPER_ADMIN).
          policy: effectiveLevel(approvalRequest),
          voterIds: approvalRequest.votes.map((v) => v.approverId),
        });
        if (!allowed) {
          // A re-check (the client re-emitting join-challenge for a room it
          // may already be in -- e.g. after its own role or the policy
          // changed) must be able to *revoke* membership, not just refuse to
          // grant it a second time. Without this, a socket legitimately
          // joined before an eligibility change would keep silently
          // receiving events after a failed re-check found it's no longer
          // authorized -- socket.leave() on an id the socket was never in is
          // a harmless no-op, so this is always safe to call.
          socket.leave(requestId);
          respond(DENIED);
          return;
        }

        socket.join(requestId);
        respond({ ok: true });
      } catch (err) {
        console.error("[socket join-challenge] unexpected error", err);
        respond(DENIED);
      }
    });
  });

  const sweepIntervalMs = options.sweepIntervalMs ?? DEFAULT_SWEEP_INTERVAL_MS;
  sweepHandle = setInterval(() => void sweepConnectedSockets(io), sweepIntervalMs);
  sweepHandle.unref();
}

/** Stops the revocation sweep -- used by tests so one file's timer doesn't
 * keep firing (and racing the next test file's own database state) once
 * that file has moved on. Mirrors stopEscalationService. */
export function stopSocketSecurity(): void {
  if (sweepHandle) {
    clearInterval(sweepHandle);
    sweepHandle = null;
  }
}

// Bounds how long an already-connected, already-authorized socket can keep
// receiving room events after its session is revoked or expires out from
// under it (REST's own revocation is authoritative on the very next
// request; a long-lived socket has no equivalent "next request" to hang
// that check on, so this polls instead). This only ever sees sockets
// connected to *this* process -- the default Socket.io adapter used here
// (no Redis/other adapter configured) keeps connections process-local, so
// on more than one running instance a socket connected to a different
// instance wouldn't be swept by this one. NovaForge's actual current
// deployment (render.yaml, docker-compose.yml) runs exactly one instance,
// so this is fully correct for it today; a multi-instance deployment would
// need a shared adapter to extend this sweep across instances, which is
// explicitly out of scope here.
async function sweepConnectedSockets(io: Server): Promise<void> {
  try {
    for (const socket of io.sockets.sockets.values()) {
      const sessionId = socket.data.sessionId as string | undefined;
      if (!sessionId || !(await isSessionLive(sessionId))) {
        socket.disconnect(true);
      }
    }
  } catch (err) {
    console.error("[socket security] error during revocation sweep", err);
  }
}
