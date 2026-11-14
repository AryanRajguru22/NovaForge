import { Router, type Request, type Response, type NextFunction } from "express";
import { z } from "zod";
import { AccountStatus, Prisma, Role } from "@prisma/client";
import { prisma } from "../lib/prisma.js";
import { requireAuth } from "../middleware/requireAuth.js";
import { appendAuditLog, auditedTransaction } from "../lib/audit.js";
import { beginStepUp, recordStepUpCounter } from "../lib/stepUp.js";
import { issueEnrollmentToken } from "../lib/enrollment.js";
import {
  enforceGovernanceStepUp,
  governanceStepUpOptions,
  governanceTrust,
  lockSuperAdminSet,
} from "../lib/governance.js";
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

/** A refusal decided inside a transaction; rolls it back and maps to an HTTP response. */
class UsersRouteError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
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

// --- Governance mutations (Phase 1) ---
//
// Roles, vote weights, account status and deletion decide who may approve
// what, so each requires on the server: SUPER_ADMIN, sufficient effective
// session trust, and a fresh single-use passkey assertion (`response` in the
// body, from POST /users/governance/step-up/options). Refusals of trust and
// step-up are audited (server/src/lib/governance.ts).
//
// "Never leave zero active super admins" is checked inside the transaction
// behind an advisory lock (lockSuperAdminSet). Checking outside it let two
// super admins demote or disable each other concurrently: each saw the other
// still active and both passed.

usersRouter.post(
  "/governance/step-up/options",
  requireAuth,
  requireSuperAdmin,
  governanceTrust("user:step-up"),
  governanceStepUpOptions("user-governance"),
);

function respondUsersError(err: unknown, res: Response): boolean {
  if (err instanceof UsersRouteError) {
    res.status(err.status).json({ error: err.message });
    return true;
  }
  return false;
}

const updateRoleSchema = z.object({
  role: z.nativeEnum(Role),
});

usersRouter.patch("/:id/role", requireAuth, requireSuperAdmin, governanceTrust("user:role"), async (req, res) => {
  const parsed = updateRoleSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }
  const stepUp = await enforceGovernanceStepUp(req, res, "user-governance", "user:role");
  if (!stepUp) return;

  try {
    const outcome = await auditedTransaction(async (tx) => {
      await lockSuperAdminSet(tx);
      const target = await tx.user.findUnique({ where: { id: req.params.id } });
      if (!target) throw new UsersRouteError(404, "User not found");

      // The super-admin role is the only thing that can grant itself (and audit
      // access) to anyone else. If the only remaining super admin demotes
      // themselves, nobody left signed in could ever restore the role. Block only
      // that specific case.
      if (target.role === Role.SUPER_ADMIN && parsed.data.role !== Role.SUPER_ADMIN) {
        const remaining = await tx.user.count({ where: { role: Role.SUPER_ADMIN, status: AccountStatus.ACTIVE } });
        if (remaining <= 1) throw new UsersRouteError(400, "Cannot remove the last super admin");
      }

      await recordStepUpCounter(tx, stepUp);
      if (target.role === parsed.data.role) return { id: target.id, role: target.role };

      const result = await tx.user.update({
        where: { id: target.id },
        data: { role: parsed.data.role },
      });
      await appendAuditLog(tx, {
        entityType: "User",
        entityId: target.id,
        event: "ROLE_CHANGED",
        actorId: req.user!.id,
        metadata: { from: target.role, to: result.role, stepUpCredentialId: stepUp.credentialId },
      });
      return { id: result.id, role: result.role };
    });
    res.json(outcome);
  } catch (err) {
    if (!respondUsersError(err, res)) throw err;
  }
});

const updateWeightSchema = z.object({
  voteWeight: z.number().int().min(1).max(10),
});

// A WEIGHTED policy's outcome depends entirely on how much each approver's
// vote counts, so changing that is exactly as sensitive as changing a role.
// (A change applies to votes cast afterwards; votes already cast keep the
// weight recorded on them -- ApprovalVote.weightAtVote.)
usersRouter.patch("/:id/weight", requireAuth, requireSuperAdmin, governanceTrust("user:weight"), async (req, res) => {
  const parsed = updateWeightSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }
  const stepUp = await enforceGovernanceStepUp(req, res, "user-governance", "user:weight");
  if (!stepUp) return;

  try {
    const outcome = await auditedTransaction(async (tx) => {
      const target = await tx.user.findUnique({ where: { id: req.params.id } });
      if (!target) throw new UsersRouteError(404, "User not found");

      await recordStepUpCounter(tx, stepUp);
      if (target.voteWeight === parsed.data.voteWeight) return { id: target.id, voteWeight: target.voteWeight };

      const result = await tx.user.update({
        where: { id: target.id },
        data: { voteWeight: parsed.data.voteWeight },
      });
      await appendAuditLog(tx, {
        entityType: "User",
        entityId: target.id,
        event: "VOTE_WEIGHT_CHANGED",
        actorId: req.user!.id,
        metadata: { from: target.voteWeight, to: result.voteWeight, stepUpCredentialId: stepUp.credentialId },
      });
      return { id: result.id, voteWeight: result.voteWeight };
    });
    res.json(outcome);
  } catch (err) {
    if (!respondUsersError(err, res)) throw err;
  }
});

const updateStatusSchema = z.object({
  status: z.nativeEnum(AccountStatus),
  reason: z.string().trim().max(500).optional(),
});

// Suspending or disabling an account takes effect immediately: the status
// change, deletion of every session, revocation of outstanding enrollment
// tokens, and the audit event commit together. isSessionLive also refuses
// any session of a non-ACTIVE user, so the status is authoritative on its own.
usersRouter.patch("/:id/status", requireAuth, requireSuperAdmin, governanceTrust("user:status"), async (req, res) => {
  const parsed = updateStatusSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }
  const { status, reason } = parsed.data;
  const stepUp = await enforceGovernanceStepUp(req, res, "user-governance", "user:status");
  if (!stepUp) return;

  try {
    const result = await auditedTransaction(async (tx) => {
      await lockSuperAdminSet(tx);
      const target = await tx.user.findUnique({ where: { id: req.params.id } });
      if (!target) throw new UsersRouteError(404, "User not found");
      if (target.id === req.user!.id) throw new UsersRouteError(400, "You cannot change your own account status");
      if (target.status === status) return { id: target.id, status: target.status, changed: false };
      if (target.role === Role.SUPER_ADMIN && status !== AccountStatus.ACTIVE) {
        const remaining = await tx.user.count({ where: { role: Role.SUPER_ADMIN, status: AccountStatus.ACTIVE } });
        if (remaining <= 1) throw new UsersRouteError(400, "Cannot deactivate the last active super admin");
      }

      await recordStepUpCounter(tx, stepUp);
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
        metadata: {
          from: target.status,
          to: status,
          reason: reason ?? null,
          sessionsRevoked,
          stepUpCredentialId: stepUp.credentialId,
        },
      });
      return { id: updated.id, status: updated.status, changed: true };
    });

    if (result.changed && result.status !== AccountStatus.ACTIVE) disconnectUserSockets(result.id);
    res.json({ id: result.id, status: result.status });
  } catch (err) {
    if (!respondUsersError(err, res)) throw err;
  }
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

usersRouter.post("/:id/enrollment-token", requireAuth, requireSuperAdmin, governanceTrust("user:enrollment-token"), async (req, res) => {
  const stepUp = await enforceGovernanceStepUp(req, res, "enrollment-token", "user:enrollment-token");
  if (!stepUp) return;

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
});

// An invitation can create a SUPER_ADMIN, so it is a role-granting path: same trust check, fresh
// passkey proof (`response` in the body) and audited refusals as the other governance mutations.
usersRouter.post("/invitations", requireAuth, requireSuperAdmin, governanceTrust("user:invite"), async (req, res) => {
  const parsed = inviteSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }
  const { email, name, role } = parsed.data;

  const stepUp = await enforceGovernanceStepUp(req, res, "enrollment-token", "user:invite");
  if (!stepUp) return;

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
usersRouter.delete("/:id", requireAuth, requireSuperAdmin, governanceTrust("user:delete"), async (req, res) => {
  const stepUp = await enforceGovernanceStepUp(req, res, "user-governance", "user:delete");
  if (!stepUp) return;

  let deletedId: string;
  try {
    deletedId = await auditedTransaction(async (tx) => {
      await lockSuperAdminSet(tx);
      const target = await tx.user.findUnique({ where: { id: req.params.id } });
      if (!target) throw new UsersRouteError(404, "User not found");
      if (target.id === req.user!.id) throw new UsersRouteError(400, "Cannot delete your own account while signed in");
      if (target.role === Role.SUPER_ADMIN) {
        const remaining = await tx.user.count({ where: { role: Role.SUPER_ADMIN } });
        if (remaining <= 1) throw new UsersRouteError(400, "Cannot delete the last super admin");
      }

      await recordStepUpCounter(tx, stepUp);
      await tx.credential.deleteMany({ where: { userId: target.id } });
      await tx.session.deleteMany({ where: { userId: target.id } });
      await tx.enrollmentToken.deleteMany({ where: { userId: target.id } });
      await tx.user.delete({ where: { id: target.id } });
      await appendAuditLog(tx, {
        entityType: "User",
        entityId: target.id,
        event: "USER_DELETED",
        actorId: req.user!.id,
        metadata: { email: target.email, name: target.name, role: target.role, stepUpCredentialId: stepUp.credentialId },
      });
      return target.id;
    });
  } catch (err) {
    if (respondUsersError(err, res)) return;
    if (isForeignKeyRestrictionError(err)) {
      res.status(409).json({
        error: "Cannot delete a user with existing sensitive actions or votes on record; disable the account instead",
      });
      return;
    }
    throw err;
  }

  disconnectUserSockets(deletedId);
  res.status(204).end();
});
