import { randomBytes } from "node:crypto";
import type { Prisma } from "@prisma/client";
import { sha256Hex } from "./canonicalJson.js";
import { appendAuditLog } from "./audit.js";

// Enrollment tokens: the only way to attach a passkey to an existing account.
//
// A token is a 256-bit random bearer capability for exactly one account,
// valid once and for a short time. Only SHA-256(token) is stored, so a
// database read doesn't yield usable tokens. Issuing a new token revokes any
// outstanding one for the same account. Issuance and redemption are both
// audited in the same transaction as the write they record.

export const ENROLLMENT_TOKEN_TTL_MS = 24 * 60 * 60 * 1000;
const TOKEN_PREFIX = "nfenr_";

export function hashEnrollmentToken(token: string): string {
  return sha256Hex(token);
}

export function isWellFormedEnrollmentToken(token: unknown): token is string {
  return typeof token === "string" && /^nfenr_[A-Za-z0-9_-]{43}$/.test(token);
}

export async function issueEnrollmentToken(
  tx: Prisma.TransactionClient,
  input: { userId: string; createdById: string | null; ttlMs?: number; reason: string },
): Promise<{ token: string; tokenId: string; expiresAt: Date }> {
  const now = new Date();
  await tx.enrollmentToken.updateMany({
    where: { userId: input.userId, usedAt: null, revokedAt: null },
    data: { revokedAt: now },
  });
  const token = `${TOKEN_PREFIX}${randomBytes(32).toString("base64url")}`;
  const expiresAt = new Date(now.getTime() + (input.ttlMs ?? ENROLLMENT_TOKEN_TTL_MS));
  const record = await tx.enrollmentToken.create({
    data: { userId: input.userId, tokenHash: hashEnrollmentToken(token), createdById: input.createdById, expiresAt },
  });
  await appendAuditLog(tx, {
    entityType: "User",
    entityId: input.userId,
    event: "ENROLLMENT_TOKEN_ISSUED",
    actorId: input.createdById,
    metadata: { enrollmentTokenId: record.id, expiresAt: expiresAt.toISOString(), reason: input.reason },
  });
  return { token, tokenId: record.id, expiresAt };
}
