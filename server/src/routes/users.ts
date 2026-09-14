import { Router, type Request, type Response, type NextFunction } from "express";
import { z } from "zod";
import { AccountStatus, Prisma, Role } from "@prisma/client";
import type { AuthenticationResponseJSON } from "@simplewebauthn/types";
import { prisma } from "../lib/prisma.js";
import { requireAuth } from "../middleware/requireAuth.js";
import { appendAuditLog, auditedTransaction } from "../lib/audit.js";
import { beginStepUp, recordStepUpCounter, verifyStepUp } from "../lib/stepUp.js";
import { issueEnrollmentToken } from "../lib/enrollment.js";
import { io } from "../app.js";

export const usersRouter = Router();

// Deleting a user whose SensitiveAction/ApprovalVote rows still reference
// them should always surface as this specific, anticipated 409 -- but Prisma
// doesn't reliably wrap this failure as PrismaClientKnownRequestError/P2003.
// A RESTRICT violation from Postgres can instead come back as
// PrismaClientUnknownRequestError, carrying the raw connector error (SQLSTATE
// 23503 foreign_key_violation, or 23001 restrict_violation) only in its
// message text. Checking both covers whichever shape Prisma produces.
function isForeignKeyRestrictionError(err: unknown): boolean {
  if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2003") return true;
  if (err instanceof Error && /\b(23503|23001)\b/.test(err.message)) return true;
  return false;
}

function isUniqueViolation(err: unknown): boolean {
  if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") return true;
  return err instanceof Error && /\b23505\b/.test(err.message);
}

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

/** Drops live Socket.io connections for a user on this process immediately,
 * rather than waiting for the periodic revocation sweep. */
function disconnectUserSockets(userId: string): void {
  for (const socket of io.sockets.sockets.values()) {
    if (socket.data.userId === userId) socket.disconnect(true);
  }
}

usersRouter.get("/", requireAuth, requireSuperAdmin, async (_req, res) => {
  const users = await prisma.user.findMany({
    orderBy: { name: "asc" },
    select: { id: true, email: true, name: true, role: true, status: true, voteWeight: true, createdAt: true },
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
  // themselves, nobody left signed in could ever restore the role. Block only
  // that specific case.
  if (target.role === Role.SUPER_ADMIN && parsed.data.role !== Role.SUPER_ADMIN) {
    const remaining = await prisma.user.count({ where: { role: Role.SUPER_ADMIN, status: AccountStatus.ACTIVE } });
    if (remaining <= 1) {
      res.status(400).json({ error: "Cannot remove the last super admin" });
      return;
    }
  }

  if (target.role === parsed.data.role) {
    res.json({ id: target.id, role: target.role });
    return;
  }

  const updated = await auditedTransaction(async (tx) => {
    const result = await tx.user.update({
      where: { id: target.id },
      data: { role: parsed.data.role },
    });
    await appendAuditLog(tx, {
      entityType: "User",
      entityId: target.id,
      event: "ROLE_CHANGED",
      actorId: req.user!.id,
      metadata: { from: target.role, to: result.role },
    });
    return result;
  });

  res.json({ id: updated.id, role: updated.role });
});

const updateWeightSchema = z.object({
  voteWeight: z.number().int().min(1).max(10),
});

// A WEIGHTED policy's outcome depends entirely on how much each approver's
// vote counts, so changing that is exactly as sensitive as changing a role.
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

  const updated = await auditedTransaction(async (tx) => {
    const result = await tx.user.update({
      where: { id: target.id },
      data: { voteWeight: parsed.data.voteWeight },
    });
    await appendAuditLog(tx, {
      entityType: "User",
      entityId: target.id,
      event: "VOTE_WEIGHT_CHANGED",
      actorId: req.user!.id,
      metadata: { from: target.voteWeight, to: result.voteWeight },
    });
    return result;
  });

  res.json({ id: updated.id, voteWeight: updated.voteWeight });
});

const updateStatusSchema = z.object({
  status: z.nativeEnum(AccountStatus),
  reason: z.string().trim().max(500).optional(),
});

// Suspending or disabling an account takes effect immediately: the status
// change, deletion of every session, revocation of outstanding enrollment
// tokens, and the audit event commit together. isSessionLive also refuses
// any session of a non-ACTIVE user, so the status is authoritative on its own.
usersRouter.patch("/:id/status", requireAuth, requireSuperAdmin, async (req, res) => {
  const parsed = updateStatusSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }
  const { status, reason } = parsed.data;

  const target = await prisma.user.findUnique({ where: { id: req.params.id } });
  if (!target) {
    res.status(404).json({ error: "User not found" });
    return;
  }
  if (target.id === req.user!.id) {
    res.status(400).json({ error: "You cannot change your own account status" });
    return;
  }
  if (target.status === status) {
    res.json({ id: target.id, status: target.status });
    return;
  }
  if (target.role === Role.SUPER_ADMIN && status !== AccountStatus.ACTIVE) {
    const remaining = await prisma.user.count({ where: { role: Role.SUPER_ADMIN, status: AccountStatus.ACTIVE } });
    if (remaining <= 1) {
      res.status(400).json({ error: "Cannot deactivate the last active super admin" });
      return;
    }
  }

  const result = await auditedTransaction(async (tx) => {
    const updated = await tx.user.update({
      where: { id: target.id },
      data: { status, statusChangedAt: new Date() },
    });
    let sessionsRevoked = 0;
    if (status !== AccountStatus.ACTIVE) {
      sessionsRevoked = (await tx.session.deleteMany({ where: { userId: target.id } })).count;
      await tx.enrollmentToken.updateMany({
        where: { userId: target.id, usedAt: null, revokedAt: null },
        data: { revokedAt: new Date() },
      });
    }
    await appendAuditLog(tx, {
      entityType: "User",
      entityId: target.id,
      event: "ACCOUNT_STATUS_CHANGED",
      actorId: req.user!.id,
      metadata: { from: target.status, to: status, reason: reason ?? null, sessionsRevoked },
    });
    return updated;
  });

  if (status !== AccountStatus.ACTIVE) disconnectUserSockets(target.id);
  res.json({ id: result.id, status: result.status });
});

// --- Enrollment (P0-1) ---
//
// Issuing an enrollment token hands out the ability to add a passkey to an
// account, so it requires a super admin AND a fresh passkey step-up
// immediately beforehand. The token is returned exactly once.

usersRouter.post("/step-up/options", requireAuth, requireSuperAdmin, async (req, res) => {
  const options = await beginStepUp(req.user!.id, "enrollment-token");
  if (!options) {
    res.status(400).json({ error: "No passkeys registered for this account" });
    return;
  }
  res.json(options);
});

const stepUpBody = z.object({
  response: z.custom<AuthenticationResponseJSON>((v) => typeof v === "object" && v !== null),
});

usersRouter.post("/:id/enrollment-token", requireAuth, requireSuperAdmin, async (req, res) => {
  const parsed = stepUpBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Passkey confirmation required" });
    return;
  }
  const stepUp = await verifyStepUp(req.user!.id, "enrollment-token", parsed.data.response);
  if (!stepUp.ok) {
    res.status(stepUp.status).json({ error: stepUp.error });
    return;
  }

  const target = await prisma.user.findUnique({ where: { id: req.params.id } });
  if (!target) {
    res.status(404).json({ error: "User not found" });
    return;
  }
  if (target.status !== AccountStatus.ACTIVE) {
    res.status(400).json({ error: "Enrollment links can only be issued for active accounts" });
    return;
  }

  const issued = await auditedTransaction(async (tx) => {
    await recordStepUpCounter(tx, stepUp);
    return issueEnrollmentToken(tx, { userId: target.id, createdById: req.user!.id, reason: "admin_issued" });
  });

  res.status(201).json({ token: issued.token, expiresAt: issued.expiresAt });
});

const inviteSchema = z.object({
  email: z.string().trim().toLowerCase().email(),
  name: z.string().trim().min(1).max(120),
  role: z.nativeEnum(Role).default(Role.MEMBER),
  response: z.custom<AuthenticationResponseJSON>((v) => typeof v === "object" && v !== null),
});

usersRouter.post("/invitations", requireAuth, requireSuperAdmin, async (req, res) => {
  const parsed = inviteSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }
  const { email, name, role, response } = parsed.data;

  const stepUp = await verifyStepUp(req.user!.id, "enrollment-token", response);
  if (!stepUp.ok) {
    res.status(stepUp.status).json({ error: stepUp.error });
    return;
  }

  try {
    const result = await auditedTransaction(async (tx) => {
      await recordStepUpCounter(tx, stepUp);
      const user = await tx.user.create({ data: { email, name, role } });
      await appendAuditLog(tx, {
        entityType: "User",
        entityId: user.id,
        event: "USER_INVITED",
        actorId: req.user!.id,
        metadata: { email, role },
      });
      const issued = await issueEnrollmentToken(tx, { userId: user.id, createdById: req.user!.id, reason: "invitation" });
      return { user, issued };
    });
    res.status(201).json({
      user: { id: result.user.id, email: result.user.email, name: result.user.name, role: result.user.role },
      token: result.issued.token,
      expiresAt: result.issued.expiresAt,
    });
  } catch (err) {
    if (isUniqueViolation(err)) {
      res.status(409).json({ error: "A user with this email already exists" });
      return;
    }
    throw err;
  }
});

// Deleting a user is only safe once their approval-history rows are gone:
// SensitiveAction.requestedBy and ApprovalVote.approver are both
// ON DELETE RESTRICT (unlike AuditLog.actorId, which is SET NULL) -- that's
// deliberate, so a delete can never silently erase who requested or approved
// something. Accounts with history should be DISABLED instead (see /status).
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
    await auditedTransaction(async (tx) => {
      await tx.credential.deleteMany({ where: { userId: target.id } });
      await tx.session.deleteMany({ where: { userId: target.id } });
      await tx.enrollmentToken.deleteMany({ where: { userId: target.id } });
      await tx.user.delete({ where: { id: target.id } });
      await appendAuditLog(tx, {
        entityType: "User",
        entityId: target.id,
        event: "USER_DELETED",
        actorId: req.user!.id,
        metadata: { email: target.email, name: target.name, role: target.role },
      });
    });
  } catch (err) {
    if (isForeignKeyRestrictionError(err)) {
      res.status(409).json({
        error: "Cannot delete a user with existing sensitive actions or votes on record; disable the account instead",
      });
      return;
    }
    throw err;
  }

  disconnectUserSockets(target.id);
  res.status(204).end();
});
