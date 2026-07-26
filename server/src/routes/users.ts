import { Router, type Request, type Response, type NextFunction } from "express";
import { z } from "zod";
import { Prisma, Role } from "@prisma/client";
import { prisma } from "../lib/prisma.js";
import { requireAuth } from "../middleware/requireAuth.js";
import { appendAuditLog } from "../lib/audit.js";

export const usersRouter = Router();

// Deleting a user whose SensitiveAction/ApprovalVote rows still reference
// them should always surface as this specific, anticipated 409 -- but Prisma
// doesn't reliably wrap this failure as PrismaClientKnownRequestError/P2003.
// Inside a $transaction array batch, a RESTRICT violation from Postgres can
// instead come back as PrismaClientUnknownRequestError, carrying the raw
// connector error (SQLSTATE 23503 foreign_key_violation, or 23001
// restrict_violation for a plain RESTRICT constraint like this one) only in
// its message text, not as a structured field. Checking both the known-error
// code and the raw SQLSTATE in the message covers whichever shape Prisma
// actually produces, since previously only the P2003 case was handled and
// the other fell through to an uncaught throw that crashed the whole server
// process, not just this one request.
function isForeignKeyRestrictionError(err: unknown): boolean {
  if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2003") return true;
  if (err instanceof Error && /\b(23503|23001)\b/.test(err.message)) return true;
  return false;
}

async function requireSuperAdmin(req: Request, res: Response, next: NextFunction): Promise<void> {
  if (!req.user) {
    res.status(401).json({ error: "Not authenticated" });
    return;
  }
  const user = await prisma.user.findUnique({ where: { id: req.user.id } });
  if (!user || user.role !== Role.SUPER_ADMIN) {
    res.status(403).json({ error: "Forbidden: Super admins only" });
    return;
  }
  next();
}

usersRouter.get("/", requireAuth, requireSuperAdmin, async (_req, res) => {
  const users = await prisma.user.findMany({
    orderBy: { name: "asc" },
    select: { id: true, email: true, name: true, role: true, voteWeight: true, createdAt: true },
  });
  res.json(users);
});

const updateRoleSchema = z.object({
  role: z.nativeEnum(Role),
});

usersRouter.patch("/:id/role", requireAuth, requireSuperAdmin, async (req, res) => {
  const parsed = updateRoleSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }

  const target = await prisma.user.findUnique({ where: { id: req.params.id } });
  if (!target) {
    res.status(404).json({ error: "User not found" });
    return;
  }

  // The super-admin role is the only thing that can grant itself (and audit
  // access) to anyone else. If the only remaining super admin demotes
  // themselves, nobody left signed in could ever restore the role — a
  // self-inflicted, unrecoverable lockout without going around the app
  // straight to the database. Block only that specific case; demoting some
  // *other* super admin while at least one remains is fine.
  if (target.role === Role.SUPER_ADMIN && parsed.data.role !== Role.SUPER_ADMIN) {
    const remaining = await prisma.user.count({ where: { role: Role.SUPER_ADMIN } });
    if (remaining <= 1) {
      res.status(400).json({ error: "Cannot remove the last super admin" });
      return;
    }
  }

  if (target.role === parsed.data.role) {
    res.json({ id: target.id, role: target.role });
    return;
  }

  const updated = await prisma.user.update({
    where: { id: target.id },
    data: { role: parsed.data.role },
  });

  await appendAuditLog({
    entityType: "User",
    entityId: target.id,
    event: "ROLE_CHANGED",
    actorId: req.user!.id,
    metadata: { from: target.role, to: updated.role },
  });

  res.json({ id: updated.id, role: updated.role });
});

const updateWeightSchema = z.object({
  voteWeight: z.number().int().min(1).max(10),
});

// A WEIGHTED policy's outcome depends entirely on how much each approver's
// vote counts, so changing that is exactly as sensitive as changing a role --
// same super-admin gate as /role above.
usersRouter.patch("/:id/weight", requireAuth, requireSuperAdmin, async (req, res) => {
  const parsed = updateWeightSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }

  const target = await prisma.user.findUnique({ where: { id: req.params.id } });
  if (!target) {
    res.status(404).json({ error: "User not found" });
    return;
  }

  if (target.voteWeight === parsed.data.voteWeight) {
    res.json({ id: target.id, voteWeight: target.voteWeight });
    return;
  }

  const updated = await prisma.user.update({
    where: { id: target.id },
    data: { voteWeight: parsed.data.voteWeight },
  });

  await appendAuditLog({
    entityType: "User",
    entityId: target.id,
    event: "VOTE_WEIGHT_CHANGED",
    actorId: req.user!.id,
    metadata: { from: target.voteWeight, to: updated.voteWeight },
  });

  res.json({ id: updated.id, voteWeight: updated.voteWeight });
});

// Deleting a user is only safe once their approval-history rows are gone:
// SensitiveAction.requestedBy and ApprovalVote.approver are both
// ON DELETE RESTRICT (unlike AuditLog.actorId, which is SET NULL) -- that's
// deliberate, so a delete can never silently erase who requested or approved
// something. Credential/Session are also RESTRICT but are just device data,
// so those are cleared first in the same transaction.
usersRouter.delete("/:id", requireAuth, requireSuperAdmin, async (req, res) => {
  const target = await prisma.user.findUnique({ where: { id: req.params.id } });
  if (!target) {
    res.status(404).json({ error: "User not found" });
    return;
  }

  if (target.id === req.user!.id) {
    res.status(400).json({ error: "Cannot delete your own account while signed in" });
    return;
  }

  if (target.role === Role.SUPER_ADMIN) {
    const remaining = await prisma.user.count({ where: { role: Role.SUPER_ADMIN } });
    if (remaining <= 1) {
      res.status(400).json({ error: "Cannot delete the last super admin" });
      return;
    }
  }

  try {
    await prisma.$transaction([
      prisma.credential.deleteMany({ where: { userId: target.id } }),
      prisma.session.deleteMany({ where: { userId: target.id } }),
      prisma.user.delete({ where: { id: target.id } }),
    ]);
  } catch (err) {
    if (isForeignKeyRestrictionError(err)) {
      res.status(409).json({
        error: "Cannot delete a user with existing sensitive actions or votes on record",
      });
      return;
    }
    throw err;
  }

  await appendAuditLog({
    entityType: "User",
    entityId: target.id,
    event: "USER_DELETED",
    actorId: req.user!.id,
    metadata: { email: target.email, name: target.name, role: target.role },
  });

  res.status(204).end();
});
