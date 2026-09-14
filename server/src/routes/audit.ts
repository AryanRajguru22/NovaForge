import { Router, type Request, type Response, type NextFunction } from "express";
import { z } from "zod";
import { prisma } from "../lib/prisma.js";
import { requireAuth } from "../middleware/requireAuth.js";
import { getAuditChainHead, verifyAuditChain } from "../lib/audit.js";
import { AccountStatus, Role } from "@prisma/client";

export const auditRouter = Router();

async function requireSuperAdmin(req: Request, res: Response, next: NextFunction): Promise<void> {
  if (!req.user) {
    res.status(401).json({ error: "Not authenticated" });
    return;
  }
  const user = await prisma.user.findUnique({ where: { id: req.user.id } });
  if (!user || user.role !== Role.SUPER_ADMIN || user.status !== AccountStatus.ACTIVE) {
    res.status(403).json({ error: "Forbidden: Super admins only" });
    return;
  }
  next();
}

const listQuerySchema = z.object({
  cursor: z.string().uuid().optional(),
  take: z.coerce.number().int().min(1).max(200).default(50),
});

// BigInt columns (seq) aren't JSON-serializable; expose them as strings.
function serializeRow<T extends { seq: bigint }>(row: T) {
  return { ...row, seq: row.seq.toString() };
}

auditRouter.get("/", requireAuth, requireSuperAdmin, async (req, res) => {
  const parsed = listQuerySchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }
  const { cursor, take } = parsed.data;

  const rows = await prisma.auditLog.findMany({
    orderBy: { seq: "desc" },
    take,
    ...(cursor ? { skip: 1, cursor: { id: cursor } } : {}),
    include: { actor: { select: { id: true, name: true, email: true, role: true } } },
  });

  res.json({
    entries: rows.map(serializeRow),
    nextCursor: rows.length === take ? rows[rows.length - 1].id : null,
  });
});

// The current chain tip. Export and store it somewhere NovaForge's database
// operators can't rewrite; passing it back to /verify as an anchor is what
// makes a wholesale, internally consistent rewrite of the chain detectable.
auditRouter.get("/head", requireAuth, requireSuperAdmin, async (_req, res) => {
  res.json(await getAuditChainHead());
});

const verifyQuerySchema = z
  .object({
    anchorSeq: z.string().regex(/^\d+$/).optional(),
    anchorHash: z.string().regex(/^[0-9a-f]{64}$/).optional(),
  })
  .refine((q) => (q.anchorSeq === undefined) === (q.anchorHash === undefined), {
    message: "anchorSeq and anchorHash must be provided together",
  });

// Walks the whole chain. An integrity violation is surfaced as HTTP 409 with
// every detected issue -- never silently repaired.
auditRouter.get("/verify", requireAuth, requireSuperAdmin, async (req, res) => {
  const parsed = verifyQuerySchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }
  const anchor =
    parsed.data.anchorSeq && parsed.data.anchorHash
      ? { seq: BigInt(parsed.data.anchorSeq), hash: parsed.data.anchorHash }
      : undefined;
  const result = await verifyAuditChain({ anchor });
  if (!result.valid) {
    console.error("[audit] chain integrity verification FAILED", result.issues.slice(0, 5));
  }
  res.status(result.valid ? 200 : 409).json(result);
});
