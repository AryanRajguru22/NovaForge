import { createHash } from "node:crypto";
import { prisma } from "./prisma.js";

function computeHash(prevHash: string | null, payload: object): string {
  const data = JSON.stringify({ prevHash, payload });
  return createHash("sha256").update(data).digest("hex");
}

/**
 * Appends a tamper-evident audit entry: each row's hash covers the previous
 * row's hash, so rewriting history requires rewriting every row after it.
 */
export async function appendAuditLog(entry: {
  entityType: string;
  entityId: string;
  event: string;
  actorId?: string;
  metadata?: object;
}) {
  const last = await prisma.auditLog.findFirst({ orderBy: { timestamp: "desc" } });
  const prevHash = last?.hash ?? null;
  const hash = computeHash(prevHash, entry);

  return prisma.auditLog.create({
    data: { ...entry, prevHash, hash },
  });
}

/** Walks the chain and verifies every row's hash matches its recorded predecessor. */
export async function verifyAuditChain(): Promise<{ valid: boolean; brokenAt?: string }> {
  const rows = await prisma.auditLog.findMany({ orderBy: { timestamp: "asc" } });
  let prevHash: string | null = null;
  for (const row of rows) {
    const expected = computeHash(prevHash, {
      entityType: row.entityType,
      entityId: row.entityId,
      event: row.event,
      actorId: row.actorId ?? undefined,
      metadata: row.metadata ?? undefined,
    });
    if (expected !== row.hash) return { valid: false, brokenAt: row.id };
    prevHash = row.hash;
  }
  return { valid: true };
}
