import { randomBytes, timingSafeEqual } from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import type { Prisma } from "@prisma/client";
import { prisma } from "./prisma.js";
import { sha256Hex } from "./canonicalJson.js";

// Service (non-human) principals.
//
// A service authenticates with `Authorization: Bearer nfsvc_<credentialId>.<secret>`.
// The secret is 32 random bytes; only its SHA-256 is stored (a fast hash is
// appropriate for a high-entropy random secret, unlike a password). The
// service must be ACTIVE, the credential unrevoked and unexpired, and the
// requested scope granted. A service credential can never be used as, or
// exchanged for, a user session.

export const SERVICE_SCOPES = ["identity:assert", "identity:introspect"] as const;
export type ServiceScope = (typeof SERVICE_SCOPES)[number];

const TOKEN_FORMAT = /^nfsvc_([0-9a-f-]{36})\.([A-Za-z0-9_-]{43})$/;

export interface AuthenticatedService {
  id: string;
  name: string;
  audience: string;
  credentialId: string;
  scopes: string[];
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      service?: AuthenticatedService;
    }
  }
}

export async function createServiceCredential(
  tx: Prisma.TransactionClient,
  serviceAccountId: string,
  expiresAt: Date | null = null,
): Promise<{ credentialId: string; token: string }> {
  const secret = randomBytes(32).toString("base64url");
  const credential = await tx.serviceCredential.create({
    data: { serviceAccountId, secretHash: sha256Hex(secret), expiresAt },
  });
  return { credentialId: credential.id, token: `nfsvc_${credential.id}.${secret}` };
}

export async function authenticateServiceToken(authorization: string | undefined): Promise<AuthenticatedService | null> {
  if (!authorization?.startsWith("Bearer ")) return null;
  const match = TOKEN_FORMAT.exec(authorization.slice("Bearer ".length).trim());
  if (!match) return null;
  const [, credentialId, secret] = match;

  const credential = await prisma.serviceCredential.findUnique({
    where: { id: credentialId },
    include: { serviceAccount: true },
  });
  // Hash comparison runs even for unknown ids so timing doesn't reveal which exist.
  const expected = Buffer.from(credential?.secretHash ?? "0".repeat(64), "hex");
  const presented = Buffer.from(sha256Hex(secret), "hex");
  const secretMatches = expected.length === presented.length && timingSafeEqual(expected, presented);
  if (!credential || !secretMatches) return null;
  if (credential.revokedAt) return null;
  if (credential.expiresAt && credential.expiresAt <= new Date()) return null;
  if (credential.serviceAccount.status !== "ACTIVE") return null;

  await prisma.serviceCredential.update({ where: { id: credential.id }, data: { lastUsedAt: new Date() } });
  const account = credential.serviceAccount;
  return { id: account.id, name: account.name, audience: account.audience, credentialId: credential.id, scopes: account.scopes };
}

export function requireService(scope: ServiceScope) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const service = await authenticateServiceToken(req.header("authorization"));
    if (!service) {
      res.status(401).json({ error: "Service authentication required" });
      return;
    }
    if (!service.scopes.includes(scope)) {
      res.status(403).json({ error: "Service is not permitted to perform this operation" });
      return;
    }
    req.service = service;
    next();
  };
}
