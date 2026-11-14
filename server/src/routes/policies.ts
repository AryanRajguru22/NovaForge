import { Router, type Request, type Response, type NextFunction } from "express";
import { z } from "zod";
import { prisma } from "../lib/prisma.js";
import { requireAuth } from "../middleware/requireAuth.js";
import { appendAuditLog, auditedTransaction } from "../lib/audit.js";
import { AccountStatus, Prisma, QuorumType, Role } from "@prisma/client";
import {
  enforceGovernanceStepUp,
  governanceStepUpOptions,
  governanceTrust,
  lockPolicyGraph,
} from "../lib/governance.js";
import { recordStepUpCounter } from "../lib/stepUp.js";
import { MAX_ESCALATIONS } from "../lib/policySnapshot.js";

export const policiesRouter = Router();

// Reusable Admin enforcement middleware. requireAuth already rejects
// non-ACTIVE accounts; the status check here is defense-in-depth so the guard
// is sound on its own, matching the sibling guards in users.ts and audit.ts.
export async function requireAdmin(req: Request, res: Response, next: NextFunction): Promise<void> {
  if (!req.user) {
    res.status(401).json({ error: "Not authenticated" });
    return;
  }
  try {
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });
    // SUPER_ADMIN is a superset of ADMIN -- it should never be locked out of
    // anything an ADMIN can do, only granted more (role/audit access).
    if (
      !user ||
      (user.role !== Role.ADMIN && user.role !== Role.SUPER_ADMIN) ||
      user.status !== AccountStatus.ACTIVE
    ) {
      res.status(403).json({ error: "Forbidden: Admins only" });
      return;
    }
    next();
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
}

// Zod schemas for request body validation
const policyCreateSchema = z.object({
  actionType: z.string().trim().min(1, "Action type is required"),
  quorumType: z.nativeEnum(QuorumType),
  minApprovals: z.number().int().nonnegative("Minimum approvals must be 0 or greater"),
  eligibleRoles: z.array(z.nativeEnum(Role)).min(1, "At least one eligible role is required"),
  fallbackPolicyId: z.string().trim().uuid("Invalid fallback policy ID").nullable().optional(),
  escalationTimeoutSec: z.number().int().positive("Escalation timeout must be a positive integer").default(300),
});

const policyUpdateSchema = z.object({
  actionType: z.string().trim().min(1, "Action type cannot be empty").optional(),
  quorumType: z.nativeEnum(QuorumType).optional(),
  minApprovals: z.number().int().nonnegative("Minimum approvals must be 0 or greater").optional(),
  eligibleRoles: z.array(z.nativeEnum(Role)).min(1, "Eligible roles cannot be empty").optional(),
  fallbackPolicyId: z.string().trim().uuid("Invalid fallback policy ID").nullable().optional(),
  escalationTimeoutSec: z.number().int().positive("Escalation timeout must be a positive integer").optional(),
});

// GET /policies - Retrieve all policies
policiesRouter.get("/", requireAuth, async (req: Request, res: Response) => {
  try {
    const policies = await prisma.approvalPolicy.findMany({
      orderBy: { actionType: "asc" },
    });
    res.json(policies);
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// --- Governance mutations (Phase 1) ---
//
// Policies define who must approve what, so changing one is the most
// sensitive thing an admin can do. Every mutation below requires, on the
// server: an ADMIN/SUPER_ADMIN, a session with sufficient effective trust, and
// a fresh single-use passkey assertion (`response` in the body, obtained from
// POST /policies/step-up/options). Editing a policy never affects requests
// that already exist -- each request carries an immutable snapshot of the
// rules it was created under (server/src/lib/policySnapshot.ts).
//
// The whole check-then-write runs in one transaction behind the policy-graph
// advisory lock, so two concurrent edits cannot jointly create a fallback
// cycle (the database trigger novaforge_policy_fallback_guard is the backstop
// for any other writer).

class PolicyRouteError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

function isFallbackGuardViolation(err: unknown): boolean {
  return err instanceof Error && /fallback (cycle|chain)/.test(err.message);
}

/** Rejects a fallback target that does not exist, closes a cycle, or makes the chain too long. */
async function assertValidFallback(
  tx: Prisma.TransactionClient,
  policyId: string | null,
  fallbackPolicyId: string,
): Promise<void> {
  let cursor: string | null = fallbackPolicyId;
  let length = 0;
  const seen = new Set<string>();
  while (cursor) {
    if (policyId !== null && cursor === policyId) {
      throw new PolicyRouteError(400, "Fallback policies must not form a cycle: this fallback eventually leads back to this policy");
    }
    if (seen.has(cursor)) {
      throw new PolicyRouteError(400, "Fallback policies must not form a cycle");
    }
    seen.add(cursor);
    const row: { fallbackPolicyId: string | null } | null = await tx.approvalPolicy.findUnique({
      where: { id: cursor },
      select: { fallbackPolicyId: true },
    });
    if (!row) {
      if (cursor === fallbackPolicyId) throw new PolicyRouteError(400, "Specified fallback policy does not exist");
      break; // dangling deeper in the chain: the chain simply ends there
    }
    length += 1;
    if (length > MAX_ESCALATIONS) {
      throw new PolicyRouteError(400, `Fallback chains may contain at most ${MAX_ESCALATIONS} fallback policies`);
    }
    cursor = row.fallbackPolicyId;
  }
}

async function nextRevisionVersion(tx: Prisma.TransactionClient, policyId: string): Promise<number> {
  const latest = await tx.approvalPolicyRevision.findFirst({
    where: { policyId },
    orderBy: { version: "desc" },
    select: { version: true },
  });
  return (latest?.version ?? 0) + 1;
}

function handlePolicyError(err: unknown, res: Response): void {
  if (err instanceof PolicyRouteError) {
    res.status(err.status).json({ error: err.message });
    return;
  }
  if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") {
    res.status(400).json({ error: "A policy with this action type already exists" });
    return;
  }
  if (isFallbackGuardViolation(err)) {
    res.status(400).json({ error: "Fallback policies must not form a cycle or exceed the maximum chain length" });
    return;
  }
  res.status(500).json({ error: "Internal server error" });
}

// POST /policies/step-up/options - begin the passkey ceremony that authorises one policy mutation.
// Declared before the /:id routes so "step-up" is never read as an id.
policiesRouter.post(
  "/step-up/options",
  requireAuth,
  requireAdmin,
  governanceTrust("policy:step-up"),
  governanceStepUpOptions("policy-governance"),
);

// GET /policies/:id - Retrieve a policy by ID
policiesRouter.get("/:id", requireAuth, async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const policy = await prisma.approvalPolicy.findUnique({
      where: { id },
    });

    if (!policy) {
      res.status(404).json({ error: "Policy not found" });
      return;
    }

    res.json(policy);
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// POST /policies - Create a new policy (Admin Only, step-up)
policiesRouter.post("/", requireAuth, requireAdmin, governanceTrust("policy:create"), async (req: Request, res: Response) => {
  const parsed = policyCreateSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request data", issues: parsed.error.issues });
    return;
  }
  const stepUp = await enforceGovernanceStepUp(req, res, "policy-governance", "policy:create");
  if (!stepUp) return;

  try {
    const data = parsed.data;
    const policy = await auditedTransaction(async (tx) => {
      await lockPolicyGraph(tx);

      const existing = await tx.approvalPolicy.findUnique({ where: { actionType: data.actionType } });
      if (existing) throw new PolicyRouteError(400, `A policy for action type "${data.actionType}" already exists`);
      if (data.fallbackPolicyId) await assertValidFallback(tx, null, data.fallbackPolicyId);

      await recordStepUpCounter(tx, stepUp);
      const created = await tx.approvalPolicy.create({
        data: {
          actionType: data.actionType,
          quorumType: data.quorumType,
          minApprovals: data.minApprovals,
          eligibleRoles: data.eligibleRoles,
          fallbackPolicyId: data.fallbackPolicyId ?? null,
          escalationTimeoutSec: data.escalationTimeoutSec,
        },
      });
      const revision = await tx.approvalPolicyRevision.create({
        data: { policyId: created.id, version: 1, changeType: "CREATED", changedById: req.user!.id, snapshot: created },
      });
      await appendAuditLog(tx, {
        entityType: "ApprovalPolicy",
        entityId: created.id,
        event: "POLICY_CREATED",
        actorId: req.user!.id,
        metadata: { ...created, revisionId: revision.id, version: 1, stepUpCredentialId: stepUp.credentialId },
      });
      return created;
    });

    res.status(201).json(policy);
  } catch (error) {
    handlePolicyError(error, res);
  }
});

// PUT /policies/:id - Update an existing policy (Admin Only, step-up)
policiesRouter.put("/:id", requireAuth, requireAdmin, governanceTrust("policy:update"), async (req: Request, res: Response) => {
  const { id } = req.params;
  const parsed = policyUpdateSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request data", issues: parsed.error.issues });
    return;
  }
  const stepUp = await enforceGovernanceStepUp(req, res, "policy-governance", "policy:update");
  if (!stepUp) return;

  try {
    const data = parsed.data;
    const updatedPolicy = await auditedTransaction(async (tx) => {
      await lockPolicyGraph(tx);
      // FOR UPDATE: request creation reads this row FOR SHARE, so a creation
      // captures either the policy entirely before or entirely after this edit.
      await tx.$queryRaw`SELECT "id" FROM "ApprovalPolicy" WHERE "id" = ${id} FOR UPDATE`;
      const existingPolicy = await tx.approvalPolicy.findUnique({ where: { id } });
      if (!existingPolicy) throw new PolicyRouteError(404, "Policy not found");

      if (data.actionType && data.actionType !== existingPolicy.actionType) {
        const duplicate = await tx.approvalPolicy.findUnique({ where: { actionType: data.actionType } });
        if (duplicate) throw new PolicyRouteError(400, `A policy for action type "${data.actionType}" already exists`);
      }

      if (data.fallbackPolicyId) {
        if (data.fallbackPolicyId === id) {
          throw new PolicyRouteError(400, "A policy cannot use itself as its fallback policy");
        }
        await assertValidFallback(tx, id, data.fallbackPolicyId);
      }

      await recordStepUpCounter(tx, stepUp);
      const updated = await tx.approvalPolicy.update({
        where: { id },
        data: {
          actionType: data.actionType !== undefined ? data.actionType : undefined,
          quorumType: data.quorumType !== undefined ? data.quorumType : undefined,
          minApprovals: data.minApprovals !== undefined ? data.minApprovals : undefined,
          eligibleRoles: data.eligibleRoles !== undefined ? data.eligibleRoles : undefined,
          fallbackPolicyId: data.fallbackPolicyId !== undefined ? data.fallbackPolicyId : undefined,
          escalationTimeoutSec: data.escalationTimeoutSec !== undefined ? data.escalationTimeoutSec : undefined,
        },
      });
      const version = await nextRevisionVersion(tx, id);
      const revision = await tx.approvalPolicyRevision.create({
        data: { policyId: id, version, changeType: "UPDATED", changedById: req.user!.id, snapshot: updated },
      });
      await appendAuditLog(tx, {
        entityType: "ApprovalPolicy",
        entityId: id,
        event: "POLICY_UPDATED",
        actorId: req.user!.id,
        metadata: {
          before: existingPolicy,
          after: updated,
          revisionId: revision.id,
          version,
          stepUpCredentialId: stepUp.credentialId,
        },
      });
      return updated;
    });

    res.json(updatedPolicy);
  } catch (error) {
    handlePolicyError(error, res);
  }
});

// DELETE /policies/:id - Delete an existing policy (Admin Only, step-up; proof in the JSON body)
policiesRouter.delete("/:id", requireAuth, requireAdmin, governanceTrust("policy:delete"), async (req: Request, res: Response) => {
  const { id } = req.params;
  const stepUp = await enforceGovernanceStepUp(req, res, "policy-governance", "policy:delete");
  if (!stepUp) return;

  try {
    await auditedTransaction(async (tx) => {
      await lockPolicyGraph(tx);
      await tx.$queryRaw`SELECT "id" FROM "ApprovalPolicy" WHERE "id" = ${id} FOR UPDATE`;
      const existingPolicy = await tx.approvalPolicy.findUnique({ where: { id } });
      if (!existingPolicy) throw new PolicyRouteError(404, "Policy not found");

      // Requests and request snapshots both reference the policy with
      // RESTRICT foreign keys, so a referenced policy can never be removed;
      // check first so the caller gets an explainable error, not a raw FK
      // violation. A policy that another policy names as its fallback is
      // refused too, so chains never silently dangle.
      const referencingRequestCount = await tx.approvalRequest.count({
        where: { OR: [{ policyId: id }, { policyLevels: { some: { policyId: id } } }] },
      });
      if (referencingRequestCount > 0) {
        throw new PolicyRouteError(400, `Cannot delete this policy: ${referencingRequestCount} approval request(s) still reference it.`);
      }
      const usedAsFallback = await tx.approvalPolicy.count({ where: { fallbackPolicyId: id } });
      if (usedAsFallback > 0) {
        throw new PolicyRouteError(
          400,
          `Cannot delete this policy: ${usedAsFallback} other polic${usedAsFallback === 1 ? "y uses" : "ies use"} it as a fallback.`,
        );
      }

      await recordStepUpCounter(tx, stepUp);
      await tx.approvalPolicy.delete({ where: { id } });
      const version = await nextRevisionVersion(tx, id);
      const revision = await tx.approvalPolicyRevision.create({
        data: { policyId: id, version, changeType: "DELETED", changedById: req.user!.id, snapshot: existingPolicy },
      });
      await appendAuditLog(tx, {
        entityType: "ApprovalPolicy",
        entityId: id,
        event: "POLICY_DELETED",
        actorId: req.user!.id,
        metadata: { ...existingPolicy, revisionId: revision.id, version, stepUpCredentialId: stepUp.credentialId },
      });
    });

    res.json({ deleted: true });
  } catch (error) {
    handlePolicyError(error, res);
  }
});
