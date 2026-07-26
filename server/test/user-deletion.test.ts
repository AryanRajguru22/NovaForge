import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { startTestServer, stopTestServer, apiRequest, createUserWithToken, cleanupUsers, runSuffix } from "./testServer.js";
import { prisma } from "../src/lib/prisma.js";

// Regression coverage for a crash: deleting a user who still has a
// SensitiveAction on record hits a Postgres RESTRICT constraint
// (SensitiveAction.requestedById), which the route is meant to turn into a
// clean 409. Prisma doesn't always surface that as the
// PrismaClientKnownRequestError/P2003 shape the route originally checked for
// -- inside a $transaction array batch it can come back as
// PrismaClientUnknownRequestError instead, which fell through to an
// uncaught throw and crashed the entire server process (not just the one
// request) in production. These tests exercise the real route end-to-end
// against real Postgres, so they'd have caught this before it shipped.
describe("user deletion", () => {
  const adminEmail = `del-admin-${runSuffix}@example.com`;
  const cleanEmail = `del-clean-${runSuffix}@example.com`;
  const referencedEmail = `del-referenced-${runSuffix}@example.com`;
  const actionType = `test:del-gate-${runSuffix}`;

  let adminToken: string;

  beforeAll(async () => {
    await startTestServer();
    await cleanupUsers([adminEmail, cleanEmail, referencedEmail]);

    const admin = await createUserWithToken({ email: adminEmail, role: "SUPER_ADMIN" });
    adminToken = admin.token;
  });

  afterAll(async () => {
    await prisma.sensitiveAction.deleteMany({ where: { type: actionType } });
    await cleanupUsers([adminEmail, cleanEmail, referencedEmail]);
    await stopTestServer();
  });

  it("deletes a user with no history cleanly", async () => {
    const { user } = await createUserWithToken({ email: cleanEmail, role: "MEMBER" });

    const res = await apiRequest(`/users/${user.id}`, { method: "DELETE", token: adminToken });
    expect(res.status).toBe(204);

    const stillThere = await prisma.user.findUnique({ where: { id: user.id } });
    expect(stillThere).toBeNull();
  });

  it("returns 409 (not a crash) when the user has a referencing SensitiveAction", async () => {
    const { user } = await createUserWithToken({ email: referencedEmail, role: "MEMBER" });
    await prisma.sensitiveAction.create({
      data: { type: actionType, payload: { note: "test" }, requestedById: user.id },
    });

    const res = await apiRequest(`/users/${user.id}`, { method: "DELETE", token: adminToken });
    expect(res.status).toBe(409);
    expect(res.data.error).toMatch(/sensitive actions or votes/i);

    // The user must still exist -- the delete should have been rejected, not
    // partially applied.
    const stillThere = await prisma.user.findUnique({ where: { id: user.id } });
    expect(stillThere).not.toBeNull();
  });

  it("the server is still responsive after that rejection -- proves no crash occurred", async () => {
    const res = await apiRequest("/auth/me", { token: adminToken });
    expect(res.status).toBe(200);
  });
});
