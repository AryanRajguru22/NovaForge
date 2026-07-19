import { Router, type Request, type Response } from "express";
import { z } from "zod";
import { prisma } from "../lib/prisma.js";
import { requireAuth } from "../middleware/requireAuth.js";
import { requireTrust } from "../middleware/requireTrust.js";
import { appendAuditLog } from "../lib/audit.js";

export const actionsRouter = Router();

const actionCreateSchema = z.object({
  type: z.string().trim().min(1, "Action type is required"),
  payload: z.unknown().refine((val) => val !== undefined && val !== null, {
    message: "Payload is required",
  }),
});

// POST /actions - Create a SensitiveAction
actionsRouter.post("/", requireAuth, requireTrust(), async (req: Request, res: Response) => {
  const parsed = actionCreateSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request data", issues: parsed.error.issues });
    return;
  }

  const { type, payload } = parsed.data;

  try {
    // Resolve matching ApprovalPolicy
    const policy = await prisma.approvalPolicy.findUnique({
      where: { actionType: type },
    });

    if (!policy) {
      res.status(400).json({ error: `No approval policy configured for action type "${type}"` });
      return;
    }

    // Create action and linked approval request atomically
    const { action, approvalRequest } = await prisma.$transaction(async (tx) => {
      const newAction = await tx.sensitiveAction.create({
        data: {
          type,
          payload: payload as any,
          requestedById: req.user!.id,
        },
      });

      const newRequest = await tx.approvalRequest.create({
        data: {
          actionId: newAction.id,
          policyId: policy.id,
          expiresAt: new Date(Date.now() + policy.escalationTimeoutSec * 1000),
        },
      });

      return { action: newAction, approvalRequest: newRequest };
    });

    // Record action creation event in the audit log
    await appendAuditLog({
      entityType: "SensitiveAction",
      entityId: action.id,
      event: "ACTION_CREATED",
      actorId: req.user!.id,
      metadata: {
        type: action.type,
        policyId: policy.id,
        approvalRequestId: approvalRequest.id,
        expiresAt: approvalRequest.expiresAt,
      },
    });

    res.status(201).json({
      action: {
        id: action.id,
        type: action.type,
        payload: action.payload,
        status: action.status,
        createdAt: action.createdAt,
      },
      approvalRequest: {
        id: approvalRequest.id,
        status: approvalRequest.status,
        expiresAt: approvalRequest.expiresAt,
      },
    });
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /actions - Retrieve all actions submitted by the authenticated user
actionsRouter.get("/", requireAuth, async (req: Request, res: Response) => {
  try {
    const actions = await prisma.sensitiveAction.findMany({
      where: { requestedById: req.user!.id },
      include: {
        requestedBy: {
          select: { id: true, email: true, name: true, role: true },
        },
        approvalRequest: {
          include: {
            policy: true,
            votes: {
              include: {
                approver: {
                  select: { id: true, email: true, name: true, role: true },
                },
              },
              orderBy: { timestamp: "asc" },
            },
          },
        },
      },
      orderBy: { createdAt: "desc" },
    });
    res.json(actions);
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /actions/:id - Retrieve action details, approval request, policy, and votes
actionsRouter.get("/:id", requireAuth, async (req: Request, res: Response) => {
  const { id } = req.params;

  try {
    const action = await prisma.sensitiveAction.findUnique({
      where: { id },
      include: {
        requestedBy: {
          select: {
            id: true,
            email: true,
            name: true,
            role: true,
          },
        },
        approvalRequest: {
          include: {
            policy: true,
            votes: {
              include: {
                approver: {
                  select: {
                    id: true,
                    email: true,
                    name: true,
                    role: true,
                  },
                },
              },
              orderBy: { timestamp: "asc" },
            },
          },
        },
      },
    });

    if (!action) {
      res.status(404).json({ error: "Action not found" });
      return;
    }

    res.json({
      action: {
        id: action.id,
        type: action.type,
        payload: action.payload,
        status: action.status,
        createdAt: action.createdAt,
        requestedBy: action.requestedBy,
      },
      approvalRequest: action.approvalRequest ? {
        id: action.approvalRequest.id,
        status: action.approvalRequest.status,
        expiresAt: action.approvalRequest.expiresAt,
        policy: action.approvalRequest.policy,
        votes: action.approvalRequest.votes.map((v) => ({
          id: v.id,
          decision: v.decision,
          signature: v.signature,
          deviceId: v.deviceId,
          timestamp: v.timestamp,
          approver: v.approver,
        })),
      } : null,
    });
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});
