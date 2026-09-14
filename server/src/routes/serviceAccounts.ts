import { Router, type Request, type Response, type NextFunction } from "express";
import { z } from "zod";
import { AccountStatus, Prisma, Role } from "@prisma/client";
import { prisma } from "../lib/prisma.js";
import { requireAuth } from "../middleware/requireAuth.js";
import { appendAuditLog, auditedTransaction } from "../lib/audit.js";
import { SERVICE_SCOPES, createServiceCredential } from "../lib/serviceAuth.js";

// Super-admin management of service principals. A credential's bearer
// secret is returned exactly once at creation; only its hash is stored.
// Audit rows for service principals have no human actor FK, so the acting
// super admin is the actor and the service is the entity.

export const serviceAccountsRouter = Router();

async function requireSuperAdmin(req: Request, res: Response, next: NextFunction): Promise<void> {
  const user = req.user ? await prisma.user.findUnique({ where: { id: req.user.id } }) : null;
  if (!user || user.role !== Role.SUPER_ADMIN || user.status !== AccountStatus.ACTIVE) {
    res.status(403).json({ error: "Forbidden: Super admins only" });
    return;
  }
  next();
}

const publicFields = { id: true, name: true, audience: true, status: true, scopes: true, createdAt: true } as const;

serviceAccountsRouter.get("/", requireAuth, requireSuperAdmin, async (_req, res) => {
  res.json(await prisma.serviceAccount.findMany({ select: publicFields, orderBy: { name: "asc" } }));
});

const createSchema = z.object({
  name: z.string().trim().min(1).max(100),
  audience: z.string().trim().min(1).max(200).regex(/^[A-Za-z0-9._:/-]+$/),
  scopes: z.array(z.enum(SERVICE_SCOPES)).min(1),
});

serviceAccountsRouter.post("/", requireAuth, requireSuperAdmin, async (req, res) => {
  const parsed = createSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }
  try {
    const account = await auditedTransaction(async (tx) => {
      const created = await tx.serviceAccount.create({
        data: { ...parsed.data, createdById: req.user!.id },
        select: publicFields,
      });
      await appendAuditLog(tx, {
        entityType: "ServiceAccount",
        entityId: created.id,
        event: "SERVICE_ACCOUNT_CREATED",
        actorId: req.user!.id,
        metadata: { name: created.name, audience: created.audience, scopes: created.scopes },
      });
      return created;
    });
    res.status(201).json(account);
  } catch (err) {
    if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") {
      res.status(409).json({ error: "A service account with this name or audience already exists" });
      return;
    }
    throw err;
  }
});

const credentialSchema = z.object({ expiresInDays: z.number().int().min(1).max(365).optional() });

serviceAccountsRouter.post("/:id/credentials", requireAuth, requireSuperAdmin, async (req, res) => {
  const parsed = credentialSchema.safeParse(req.body ?? {});
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }
  const account = await prisma.serviceAccount.findUnique({ where: { id: req.params.id } });
  if (!account) {
    res.status(404).json({ error: "Service account not found" });
    return;
  }
  const expiresAt = parsed.data.expiresInDays ? new Date(Date.now() + parsed.data.expiresInDays * 86_400_000) : null;
  const issued = await auditedTransaction(async (tx) => {
    const credential = await createServiceCredential(tx, account.id, expiresAt);
    await appendAuditLog(tx, {
      entityType: "ServiceAccount",
      entityId: account.id,
      event: "SERVICE_CREDENTIAL_ISSUED",
      actorId: req.user!.id,
      metadata: { credentialId: credential.credentialId, expiresAt },
    });
    return credential;
  });
  res.status(201).json({ credentialId: issued.credentialId, token: issued.token, expiresAt });
});

serviceAccountsRouter.delete("/:id/credentials/:credentialId", requireAuth, requireSuperAdmin, async (req, res) => {
  const revoked = await auditedTransaction(async (tx) => {
    const result = await tx.serviceCredential.updateMany({
      where: { id: req.params.credentialId, serviceAccountId: req.params.id, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    if (result.count === 1) {
      await appendAuditLog(tx, {
        entityType: "ServiceAccount",
        entityId: req.params.id,
        event: "SERVICE_CREDENTIAL_REVOKED",
        actorId: req.user!.id,
        metadata: { credentialId: req.params.credentialId },
      });
    }
    return result.count === 1;
  });
  if (!revoked) {
    res.status(404).json({ error: "Active credential not found" });
    return;
  }
  res.json({ revoked: true });
});

const statusSchema = z.object({ status: z.nativeEnum(AccountStatus) });

serviceAccountsRouter.patch("/:id/status", requireAuth, requireSuperAdmin, async (req, res) => {
  const parsed = statusSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }
  const account = await prisma.serviceAccount.findUnique({ where: { id: req.params.id } });
  if (!account) {
    res.status(404).json({ error: "Service account not found" });
    return;
  }
  const updated = await auditedTransaction(async (tx) => {
    const result = await tx.serviceAccount.update({ where: { id: account.id }, data: { status: parsed.data.status }, select: publicFields });
    await appendAuditLog(tx, {
      entityType: "ServiceAccount",
      entityId: account.id,
      event: "SERVICE_ACCOUNT_STATUS_CHANGED",
      actorId: req.user!.id,
      metadata: { from: account.status, to: parsed.data.status },
    });
    return result;
  });
  res.json(updated);
});
