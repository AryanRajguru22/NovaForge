import type { NextFunction, Request, Response } from "express";

// Baseline hardening headers for every response.
//
// API and OAuth responses are never meant to be rendered or framed, so they get
// a CSP of `default-src 'none'`. The authorize/logout error pages are the only
// HTML the API produces and use an inline <style>, hence the style-src.
// The single-page client is served either by nginx (see client/nginx.conf, which
// sets its own CSP) or, in the combined image, by this process: it gets a CSP
// that only allows its own scripts, styles, images and same-origin connections.

const API_CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
const SPA_CSP =
  "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; " +
  "connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";

export function securityHeaders(req: Request, res: Response, next: NextFunction): void {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  const isApi = req.path.startsWith("/api") || req.path.startsWith("/.well-known") || req.path === "/health" || req.path === "/ready";
  res.setHeader("Content-Security-Policy", isApi ? API_CSP : SPA_CSP);
  if (process.env.NODE_ENV === "production") {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  next();
}
