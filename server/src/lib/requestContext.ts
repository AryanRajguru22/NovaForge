import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";
import type { NextFunction, Request, Response } from "express";

// Per-request correlation context. The correlation id is propagated
// automatically into every audit row written while handling the request
// (server/src/lib/audit.ts), so NovaForge's security events can later be
// joined with a downstream service's own audit trail for the same request.
//
// A caller-supplied X-Request-Id is accepted only in a constrained format and
// is treated purely as a correlation label -- never as identity or authority.

interface RequestContext {
  correlationId: string;
}

const storage = new AsyncLocalStorage<RequestContext>();
const ACCEPTED_REQUEST_ID = /^[A-Za-z0-9._:-]{8,128}$/;

export function requestContextMiddleware(req: Request, res: Response, next: NextFunction): void {
  const supplied = req.header("x-request-id");
  const correlationId = supplied && ACCEPTED_REQUEST_ID.test(supplied) ? supplied : randomUUID();
  res.setHeader("X-Request-Id", correlationId);
  storage.run({ correlationId }, () => next());
}

export function getCorrelationId(): string | undefined {
  return storage.getStore()?.correlationId;
}
