import type { NextFunction, Request, Response } from "express";

interface Bucket {
  count: number;
  resetAt: number;
}

const buckets = new Map<string, Bucket>();

/**
 * Fixed-window rate limiter keyed by IP + a request field (e.g. email), so one
 * attacker guessing many emails from one IP and one attacker hammering a single
 * account from many IPs both get throttled. In-memory only — fine for a
 * single-process demo, would need a shared store (Redis) across instances.
 */
export function rateLimit(opts: { max: number; windowMs: number; keyField?: string }) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const identity = opts.keyField ? String(req.body?.[opts.keyField] ?? "") : "";
    const key = `${req.ip}:${req.path}:${identity}`;
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
