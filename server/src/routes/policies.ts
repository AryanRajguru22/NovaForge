import { Router, type Request, type Response, type NextFunction } from "express";
import { z } from "zod";
import { prisma } from "../lib/prisma.js";
import { requireAuth } from "../middleware/requireAuth.js";
import { appendAuditLog } from "../lib/audit.js";
import { QuorumType, Role } from "@prisma/client";

export const policiesRouter = Router();

// Reusable Admin enforcement middleware
async function requireAdmin(req: Request, res: Response, next: NextFunction): Promise<void> {
  if (!req.user) {
    res.status(401).json({ error: "Not authenticated" });
    return;
  }
  try {
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });
    if (!user || user.role !== Role.ADMIN) {
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

// POST /policies - Create a new policy (Admin Only)
policiesRouter.post("/", requireAuth, requireAdmin, async (req: Request, res: Response) => {
  const parsed = policyCreateSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request data", issues: parsed.error.issues });
    return;
  }

  try {
    const data = parsed.data;

    // Verify actionType uniqueness
    const existing = await prisma.approvalPolicy.findUnique({
      where: { actionType: data.actionType },
    });
    if (existing) {
      res.status(400).json({ error: `A policy for action type "${data.actionType}" already exists` });
      return;
    }

    // Verify fallbackPolicyId exists if provided
    if (data.fallbackPolicyId) {
      const fallback = await prisma.approvalPolicy.findUnique({
        where: { id: data.fallbackPolicyId },
      });
      if (!fallback) {
        res.status(400).json({ error: "Specified fallback policy does not exist" });
        return;
      }
    }

    const policy = await prisma.approvalPolicy.create({
      data: {
        actionType: data.actionType,
        quorumType: data.quorumType,
        minApprovals: data.minApprovals,
        eligibleRoles: data.eligibleRoles,
        fallbackPolicyId: data.fallbackPolicyId ?? null,
        escalationTimeoutSec: data.escalationTimeoutSec,
      },
    });

    await appendAuditLog({
      entityType: "ApprovalPolicy",
      entityId: policy.id,
      event: "POLICY_CREATED",
      actorId: req.user!.id,
      metadata: policy,
    });

    res.status(201).json(policy);
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// PUT /policies/:id - Update an existing policy (Admin Only)
policiesRouter.put("/:id", requireAuth, requireAdmin, async (req: Request, res: Response) => {
  const { id } = req.params;
  const parsed = policyUpdateSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request data", issues: parsed.error.issues });
    return;
  }

  try {
    const existingPolicy = await prisma.approvalPolicy.findUnique({
      where: { id },
    });
    if (!existingPolicy) {
      res.status(404).json({ error: "Policy not found" });
      return;
    }

    const data = parsed.data;

    // Verify actionType uniqueness if being updated
    if (data.actionType && data.actionType !== existingPolicy.actionType) {
      const duplicate = await prisma.approvalPolicy.findUnique({
        where: { actionType: data.actionType },
      });
      if (duplicate) {
        res.status(400).json({ error: `A policy for action type "${data.actionType}" already exists` });
        return;
      }
    }

    // Verify fallbackPolicyId exists and is not self
    if (data.fallbackPolicyId) {
      if (data.fallbackPolicyId === id) {
        res.status(400).json({ error: "A policy cannot use itself as its fallback policy" });
        return;
      }
      const fallback = await prisma.approvalPolicy.findUnique({
        where: { id: data.fallbackPolicyId },
      });
      if (!fallback) {
        res.status(400).json({ error: "Specified fallback policy does not exist" });
        return;
      }
    }

    const updatedPolicy = await prisma.approvalPolicy.update({
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

    await appendAuditLog({
      entityType: "ApprovalPolicy",
      entityId: id,
      event: "POLICY_UPDATED",
      actorId: req.user!.id,
      metadata: {
        before: existingPolicy,
        after: updatedPolicy,
      },
    });

    res.json(updatedPolicy);
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// DELETE /policies/:id - Delete an existing policy (Admin Only)
policiesRouter.delete("/:id", requireAuth, requireAdmin, async (req: Request, res: Response) => {
  const { id } = req.params;

  try {
    const existingPolicy = await prisma.approvalPolicy.findUnique({
      where: { id },
    });
    if (!existingPolicy) {
      res.status(404).json({ error: "Policy not found" });
      return;
    }

    // ApprovalRequest.policyId has no onDelete behavior, so Postgres defaults
    // to RESTRICT — deleting a policy that any request (past or present)
    // still references would otherwise throw a raw FK violation. Check first
    // so the caller gets an explainable error instead of a bare 500.
    const referencingRequestCount = await prisma.approvalRequest.count({ where: { policyId: id } });
    if (referencingRequestCount > 0) {
      res.status(400).json({
        error: `Cannot delete this policy: ${referencingRequestCount} approval request(s) still reference it.`,
      });
      return;
    }

    await prisma.approvalPolicy.delete({
      where: { id },
    });

    await appendAuditLog({
      entityType: "ApprovalPolicy",
      entityId: id,
      event: "POLICY_DELETED",
      actorId: req.user!.id,
      metadata: existingPolicy,
    });

    res.json({ deleted: true });
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});
