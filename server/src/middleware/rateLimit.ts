import type { NextFunction, Request, Response } from "express";

interface Bucket {
  count: number;
  resetAt: number;
}

const buckets = new Map<string, Bucket>();

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
    const identity = opts.identity ? opts.identity(req) : "";
    const key = `${req.ip}:${req.baseUrl}${req.path}:${identity}`;
    const now = Date.now();

    const bucket = buckets.get(key);
    if (!bucket || bucket.resetAt < now) {
      buckets.set(key, { count: 1, resetAt: now + opts.windowMs });
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
