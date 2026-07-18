import { createHash } from "node:crypto";
import { prisma } from "./prisma.js";

// Postgres stores `metadata` as JSONB, which does not preserve object key
// order — reading a row back and re-stringifying it can yield different key
// ordering than the object had at insert time. A plain JSON.stringify would
// then hash differently for the exact same logical data, making every
// verification of an entry with multi-key metadata falsely report tampering.
// Sorting keys recursively before stringifying makes the hash independent of
// key order on both the write and the read-back verification path.
function canonicalStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  // Match JSON.stringify's behavior of serializing via toJSON() when present
  // (e.g. Date -> ISO string), so a Date survives a JSONB round-trip with the
  // same canonical form it had before ever touching the database.
  if (typeof (value as { toJSON?: unknown }).toJSON === "function") {
    return canonicalStringify((value as { toJSON: () => unknown }).toJSON());
  }
  if (Array.isArray(value)) return `[${value.map((v) => canonicalStringify(v) ?? "null").join(",")}]`;
  // Also match JSON.stringify's behavior of dropping undefined-valued keys
  // entirely, so "key omitted" and "key present but undefined" hash the same
  // way — otherwise appendAuditLog's sparse input object and
  // verifyAuditChain's always-present reconstructed object would disagree.
  const entries = Object.keys(value as Record<string, unknown>)
    .sort()
    .map((key) => [key, canonicalStringify((value as Record<string, unknown>)[key])] as const)
    .filter((pair): pair is [string, string] => pair[1] !== undefined)
    .map(([key, val]) => `${JSON.stringify(key)}:${val}`);
  return `{${entries.join(",")}}`;
}

function computeHash(prevHash: string | null, payload: object): string {
  const data = canonicalStringify({ prevHash, payload });
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
