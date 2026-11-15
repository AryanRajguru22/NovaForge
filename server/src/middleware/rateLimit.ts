import { createHash } from "node:crypto";
import type { NextFunction, Request, Response } from "express";

interface Bucket {
  count: number;
  resetAt: number;
}

const buckets = new Map<string, Bucket>();

// Memory bound. Keys include request-controlled text (an email, a client id),
// so without a cap a client could grow this map without limit by sending
// distinct values. Expired buckets are purged first; if the map is still over
// the cap the oldest entries (Map preserves insertion order) are dropped.
// Dropping a live bucket only ever *resets* a limit, which is the safe
// direction for a first-line burst limiter -- the database-backed throttle in
// authThrottle.ts is the authoritative per-account control.
export const MAX_BUCKETS = 20_000;

function enforceBucketCap(now: number): void {
  if (buckets.size <= MAX_BUCKETS) return;
  for (const [key, bucket] of buckets) if (bucket.resetAt < now) buckets.delete(key);
  if (buckets.size <= MAX_BUCKETS) return;
  const excess = buckets.size - Math.floor(MAX_BUCKETS * 0.9);
  let removed = 0;
  for (const key of buckets.keys()) {
    if (removed++ >= excess) break;
    buckets.delete(key);
  }
}

/** Test-only: number of live buckets. */
export function bucketCount(): number {
  return buckets.size;
}

/**
 * Fixed-window rate limiter keyed by IP + route + an optional identity
 * derived from the request body. The identity is canonicalized with the same
 * rules the route itself applies (e.g. trim + lowercase for email) BEFORE it
 * becomes part of the key, so "Admin@x.com", "admin@x.com" and " ADMIN@x.com"
 * share one bucket instead of each getting a fresh budget.
 *
 * In-memory and per-process: a coarse first line of defense against bursts.
 * The authoritative per-account limit for guessable factors is the
 * database-backed throttle in server/src/lib/authThrottle.ts.
 */
export function rateLimit(opts: {
  max: number;
  windowMs: number;
  identity?: (req: Request) => string;
}) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const rawIdentity = opts.identity ? opts.identity(req) : "";
    // Long identities are hashed so a key is always short and bounded.
    const identity = rawIdentity.length > 64 ? createHash("sha256").update(rawIdentity).digest("hex") : rawIdentity;
    const key = `${req.ip}:${req.baseUrl}${req.path}:${identity}`;
    const now = Date.now();

    const bucket = buckets.get(key);
    if (!bucket || bucket.resetAt < now) {
      buckets.set(key, { count: 1, resetAt: now + opts.windowMs });
      enforceBucketCap(now);
      next();
      return;
    }

    if (bucket.count >= opts.max) {
      const retryAfterSec = Math.ceil((bucket.resetAt - now) / 1000);
      res.setHeader("Retry-After", String(retryAfterSec));
      res.status(429).json({ error: "Too many attempts, please try again later" });
      return;
    }

    bucket.count += 1;
    next();
  };
}

/** Test-only: forget all in-memory buckets. */
export function resetRateLimitBuckets(): void {
  buckets.clear();
}
