// Session trust decays 5 points per hour since the session last re-verified
// with the server (POST /auth/session/refresh). The stored Session.trustLevel
// is only rewritten at a check-in, so anything that reports trust between
// check-ins must apply this decay itself rather than trusting the stored
// value. Decay only -- the per-check-in recovery bonus belongs to the refresh
// route, since nothing else is evidence that anyone re-verified.
export const TRUST_DECAY_PER_HOUR = 5;

/** Unrounded trust after decay since lastVerifiedAt. Pure: never touches the session row. */
export function decayedTrustLevel(session: { trustLevel: number; lastVerifiedAt: Date }, now: Date = new Date()): number {
  const hoursSinceVerified = (now.getTime() - session.lastVerifiedAt.getTime()) / 3_600_000;
  return Math.max(0, session.trustLevel - TRUST_DECAY_PER_HOUR * hoursSinceVerified);
}
