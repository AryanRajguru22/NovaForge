import { prisma } from "./prisma.js";
import { appendAuditLog, auditedTransaction } from "./audit.js";

// How long a just-rotated-away refresh jti is still accepted as "this is
// almost certainly the same browser, a different request, racing the one
// that already won the rotation" rather than treated as replay. Routine
// multi-tab usage naturally self-synchronizes via the shared browser cookie
// jar -- a tab's own periodic refresh (client/src/App.tsx, every 4 minutes)
// reads whatever the browser's *current* cookie is at the moment it fires,
// not a stale in-memory copy, so by the time any later, independently-timed
// request goes out it already presents the rotated token. This window only
// ever matters for genuinely in-flight, near-simultaneous requests (e.g.
// two tabs' 401-triggered retries firing within the same instant) -- a few
// seconds is enough to absorb that without meaningfully widening a real
// attacker's replay opportunity. Deliberately a code constant, not stored
// in the database: it's a server-side policy applied at evaluation time,
// not per-session state.
export const REFRESH_ROTATION_GRACE_MS = 5_000;

export type RefreshRotationResult =
  | { outcome: "rotated"; jti: string }
  | { outcome: "grace"; jti: string }
  | { outcome: "replay" }
  | { outcome: "not_found" };

/**
 * Atomically attempts to rotate a session's refresh token from presentedJti
 * to newJti. Called from POST /session/refresh (server/src/routes/auth.ts)
 * after that route has already verified the JWT's signature, type, and
 * expiry, and confirmed payload.sub matches the session's actual owner --
 * this function only ever deals with a token that's already proven
 * authentic; its job is purely the rotation/replay state machine.
 */
export async function rotateRefreshToken(
  sessionId: string,
  presentedJti: string,
  newJti: string,
): Promise<RefreshRotationResult> {
  // The atomic compare-and-swap: this single UPDATE statement is what makes
  // rotation safe under concurrency, not any locking or in-process
  // coordination. Mirrors the exact "conditional updateMany + count check"
  // idiom already established in this codebase (server/src/lib/escalation.ts,
  // server/src/routes/approvals.ts) rather than the vulnerable
  // find-then-compare-in-JS-then-write-unconditionally shape that would
  // reopen exactly the race this exists to close.
  const rotated = await prisma.session.updateMany({
    where: { id: sessionId, currentRefreshTokenId: presentedJti },
    data: { previousRefreshTokenId: presentedJti, currentRefreshTokenId: newJti, rotatedAt: new Date() },
  });

  if (rotated.count === 1) {
    return { outcome: "rotated", jti: newJti };
  }

  // The CAS didn't match presentedJti against the row's *current* value --
  // re-read fresh rather than assume anything, since another request may
  // have just changed it (that's the whole point of getting here).
  const session = await prisma.session.findUnique({ where: { id: sessionId } });
  if (!session) {
    // Gone entirely -- most likely a concurrent replay-detection delete
    // (below) already ran for this exact race. Same effective outcome as
    // "no session" from the caller's point of view, not a fresh
    // determination of its own.
    return { outcome: "not_found" };
  }

  const withinGrace =
    session.previousRefreshTokenId === presentedJti &&
    session.rotatedAt !== null &&
    Date.now() - session.rotatedAt.getTime() <= REFRESH_ROTATION_GRACE_MS;

  if (withinGrace) {
    // Legitimate concurrent refresh: some other request already rotated
    // this exact token moments ago. Do NOT rotate again -- that would just
    // manufacture a second, divergent "current" token and immediately
    // invalidate the one the winning request already handed back to the
    // browser. Instead, hand back the *current* jti so this request
    // converges on the same token the winner established.
    return { outcome: "grace", jti: session.currentRefreshTokenId! };
  }

  // presentedJti matches neither the current token nor a very-recently-
  // rotated-away one -- genuine reuse of a token that should never be
  // presentable again. Revoke the whole session (not just "this token"):
  // requireAuth, this same refresh route, and the Socket.io revocation
  // sweep (server/src/lib/socketSecurity.ts) all already treat a missing
  // Session row as fully authoritative, so deleting it is what correctly
  // and immediately invalidates every access token, every future refresh
  // attempt, and any live sockets for this session -- one mechanism, not a
  // second, parallel revocation path that could drift out of sync with it.
  await revokeSessionForReplay(session.id, session.userId);
  return { outcome: "replay" };
}

async function revokeSessionForReplay(sessionId: string, userId: string): Promise<void> {
  // Revocation and its audit events commit atomically (P0-5): a replay
  // revocation can never exist without its REFRESH_TOKEN_REUSE_DETECTED /
  // SESSION_REVOKED record, and a record can never describe a revocation that
  // didn't happen. If the transaction fails, nothing is revoked and the route
  // surfaces an error; the presented token still cannot rotate (its jti is
  // stale), so a retry is detected as replay again rather than accepted.
  //
  // deleteMany (not delete) because a concurrent replay detection for the
  // same session may already have removed the row -- that's the intended
  // outcome, and only the transaction that actually removed it records it.
  await auditedTransaction(async (tx) => {
    const removed = await tx.session.deleteMany({ where: { id: sessionId } });
    if (removed.count === 0) return;
    await appendAuditLog(tx, {
      entityType: "Session",
      entityId: sessionId,
      event: "REFRESH_TOKEN_REUSE_DETECTED",
      metadata: { userId },
    });
    await appendAuditLog(tx, {
      entityType: "Session",
      entityId: sessionId,
      event: "SESSION_REVOKED",
      metadata: { reason: "refresh_token_reuse" },
    });
  });
}
