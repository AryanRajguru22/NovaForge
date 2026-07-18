import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { appendAuditLog, verifyAuditChain } from "../src/lib/audit.js";
import { prisma } from "../src/lib/prisma.js";

describe("audit hash chain", () => {
  const entityId = "audit-test-entity";

  afterAll(async () => {
    await prisma.auditLog.deleteMany({ where: { entityId } });
  });

  it("stays valid across a run of appended entries", async () => {
    await appendAuditLog({ entityType: "Test", entityId, event: "STEP_ONE" });
    await appendAuditLog({ entityType: "Test", entityId, event: "STEP_TWO" });
    await appendAuditLog({ entityType: "Test", entityId, event: "STEP_THREE" });

    const result = await verifyAuditChain();
    expect(result.valid).toBe(true);
  });

  it("detects tampering when a row's payload is edited after the fact", async () => {
    const entry = await appendAuditLog({ entityType: "Test", entityId, event: "STEP_FOUR" });

    // Simulate tampering: rewrite the event field without recomputing the hash.
    await prisma.auditLog.update({
      where: { id: entry.id },
      data: { event: "TAMPERED" },
    });

    const result = await verifyAuditChain();
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(entry.id);

    // Restore so later tests (and the rest of the suite's chain) aren't left broken.
    await prisma.auditLog.update({
      where: { id: entry.id },
      data: { event: "STEP_FOUR" },
    });
  });
});
