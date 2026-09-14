import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { Request, Response } from "express";
import { createUserWithToken, cleanupUsers, runSuffix } from "./testServer.js";
import { prisma } from "../src/lib/prisma.js";
import { requireAdmin } from "../src/routes/policies.js";

// requireAuth already rejects non-ACTIVE accounts, so an HTTP request can
// never reach requireAdmin with one. These tests invoke the guard directly to
// prove it is sound on its own.
describe("requireAdmin (invoked independently of requireAuth)", () => {
  const emails = {
    active: `req-admin-active-${runSuffix}@example.com`,
    suspended: `req-admin-suspended-${runSuffix}@example.com`,
    disabled: `req-admin-disabled-${runSuffix}@example.com`,
    superSuspended: `req-admin-super-suspended-${runSuffix}@example.com`,
  };
  const ids: Record<keyof typeof emails, string> = {} as never;

  beforeAll(async () => {
    await cleanupUsers(Object.values(emails));
    ids.active = (await createUserWithToken({ email: emails.active, role: "ADMIN" })).user.id;
    ids.suspended = (await createUserWithToken({ email: emails.suspended, role: "ADMIN" })).user.id;
    ids.disabled = (await createUserWithToken({ email: emails.disabled, role: "ADMIN" })).user.id;
    ids.superSuspended = (await createUserWithToken({ email: emails.superSuspended, role: "SUPER_ADMIN" })).user.id;
    await prisma.user.update({ where: { id: ids.suspended }, data: { status: "SUSPENDED" } });
    await prisma.user.update({ where: { id: ids.disabled }, data: { status: "DISABLED" } });
    await prisma.user.update({ where: { id: ids.superSuspended }, data: { status: "SUSPENDED" } });
  });

  afterAll(async () => {
    await cleanupUsers(Object.values(emails));
  });

  async function invoke(userId: string) {
    const outcome: { status?: number; body?: unknown; nextCalled: boolean } = { nextCalled: false };
    const req = { user: { id: userId } } as unknown as Request;
    const res = {
      status(code: number) {
        outcome.status = code;
        return this;
      },
      json(body: unknown) {
        outcome.body = body;
        return this;
      },
    } as unknown as Response;
    await requireAdmin(req, res, () => {
      outcome.nextCalled = true;
    });
    return outcome;
  }

  it("passes an ACTIVE admin (control)", async () => {
    const outcome = await invoke(ids.active);
    expect(outcome.nextCalled).toBe(true);
    expect(outcome.status).toBeUndefined();
  });

  it.each(["suspended", "disabled", "superSuspended"] as const)("rejects a non-ACTIVE admin (%s)", async (which) => {
    const outcome = await invoke(ids[which]);
    expect(outcome.nextCalled).toBe(false);
    expect(outcome.status).toBe(403);
    expect(outcome.body).toEqual({ error: "Forbidden: Admins only" });
  });
});
