import { Router, type Request, type Response, type NextFunction } from "express";
import { z } from "zod";
import { prisma } from "../lib/prisma.js";
import { requireAuth } from "../middleware/requireAuth.js";
import { verifyAuditChain } from "../lib/audit.js";
import { Role } from "@prisma/client";

export const auditRouter = Router();

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

const listQuerySchema = z.object({
  cursor: z.string().uuid().optional(),
  take: z.coerce.number().int().min(1).max(200).default(50),
});

auditRouter.get("/", requireAuth, requireSuperAdmin, async (req, res) => {
  const parsed = listQuerySchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }
  const { cursor, take } = parsed.data;

  const rows = await prisma.auditLog.findMany({
    orderBy: { timestamp: "desc" },
    take,
    ...(cursor ? { skip: 1, cursor: { id: cursor } } : {}),
    include: { actor: { select: { id: true, name: true, email: true, role: true } } },
  });

  res.json({
    entries: rows,
    nextCursor: rows.length === take ? rows[rows.length - 1].id : null,
  });
});

// Walks the whole hash chain and reports whether any row's hash no longer
// matches its recorded predecessor — the demonstrable proof that the ledger
// hasn't been tampered with (or, if someone hand-edits a row in the DB, a
// visible way to show exactly where the chain breaks).
auditRouter.get("/verify", requireAuth, requireSuperAdmin, async (_req, res) => {
  const result = await verifyAuditChain();
  res.json(result);
});
