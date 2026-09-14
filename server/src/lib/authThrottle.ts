import { Prisma } from "@prisma/client";
import { auditedTransaction, appendAuditLog } from "./audit.js";
import { sha256Hex } from "./canonicalJson.js";

// Persistent, per-subject throttle for guessable fallback factors (TOTP
// codes, recovery codes).
//
// Balanced model:
//   * Each subject (a canonical email, so case/whitespace variants share one
//     budget) gets MAX_ATTEMPTS attempts. The next attempt locks the subject
//     for BASE_LOCK_MS * 2^lockLevel (capped at MAX_LOCK_MS), and every
//     subsequent lock doubles until a successful sign-in resets it. Over a
//     sustained attack that bounds guessing to a few attempts per day.
//   * An attempt is reserved *before* the factor is checked, under a row lock,
//     so N concurrent guesses can't all slip past the counter.
//   * The lock applies only to the fallback factors. Passkey sign-in is never
//     throttled by this, so an attacker who deliberately locks a victim's
//     fallback factors cannot lock the victim out of their account.
//   * Nothing about whether the subject is a real account is revealed: unknown
//     emails are throttled identically.

export const MAX_ATTEMPTS = 5;
export const BASE_LOCK_MS = 15 * 60 * 1000;
export const MAX_LOCK_MS = 24 * 60 * 60 * 1000;

export type ThrottleDecision = { allowed: true } | { allowed: false; retryAfterMs: number };

export function fallbackSubject(normalizedEmail: string): string {
  return `fallback-login:${normalizedEmail}`;
}

export async function reserveAuthAttempt(subject: string, now: Date = new Date()): Promise<ThrottleDecision> {
  return auditedTransaction(async (tx) => {
    await tx.$executeRaw`
      INSERT INTO "AuthThrottle" ("subject", "attempts", "lockLevel", "updatedAt")
      VALUES (${subject}, 0, 0, ${now})
      ON CONFLICT ("subject") DO NOTHING`;
    const [row] = await tx.$queryRaw<{ attempts: number; lockLevel: number; lockedUntil: Date | null }[]>`
      SELECT "attempts", "lockLevel", "lockedUntil" FROM "AuthThrottle" WHERE "subject" = ${subject} FOR UPDATE`;

    if (row.lockedUntil && row.lockedUntil > now) {
      return { allowed: false, retryAfterMs: row.lockedUntil.getTime() - now.getTime() };
    }

    if (row.attempts >= MAX_ATTEMPTS) {
      const lockMs = Math.min(MAX_LOCK_MS, BASE_LOCK_MS * 2 ** row.lockLevel);
      const lockedUntil = new Date(now.getTime() + lockMs);
      await tx.authThrottle.update({
        where: { subject },
        data: { attempts: 0, lockLevel: row.lockLevel + 1, lockedUntil },
      });
      await appendAuditLog(tx, {
        entityType: "AuthSubject",
        // Hashed so the audit trail doesn't accumulate raw emails an attacker typed.
        entityId: sha256Hex(subject),
        event: "AUTH_FALLBACK_LOCKED",
        metadata: { lockMs, lockLevel: row.lockLevel + 1 },
      });
      return { allowed: false, retryAfterMs: lockMs };
    }

    await tx.authThrottle.update({ where: { subject }, data: { attempts: row.attempts + 1, lockedUntil: null } });
    return { allowed: true };
  });
}

/** Clears the budget after a genuine successful sign-in with this factor. */
export async function resetAuthThrottle(tx: Prisma.TransactionClient, subject: string): Promise<void> {
  await tx.authThrottle.updateMany({ where: { subject }, data: { attempts: 0, lockLevel: 0, lockedUntil: null } });
}
