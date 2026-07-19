import { Router, type Request, type Response, type NextFunction } from "express";
import { z } from "zod";
import { prisma } from "../lib/prisma.js";
import { requireAuth } from "../middleware/requireAuth.js";
import { appendAuditLog } from "../lib/audit.js";
import { Role } from "@prisma/client";

export const usersRouter = Router();

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
    select: { id: true, email: true, name: true, role: true, createdAt: true },
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
