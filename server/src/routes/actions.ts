import { Router, type Request, type Response } from "express";
import { z } from "zod";
import { randomUUID } from "node:crypto";
import { prisma } from "../lib/prisma.js";
import { requireAuth } from "../middleware/requireAuth.js";
import { requireTrust } from "../middleware/requireTrust.js";
import { appendAuditLog, auditedTransaction } from "../lib/audit.js";
import { canonicalJson, toJsonValue } from "../lib/canonicalJson.js";
import { computeSubjectDigest } from "../lib/approvalSignature.js";
import { canViewApprovalRecord } from "../lib/approvalAccess.js";

export const actionsRouter = Router();

const actionCreateSchema = z.object({
  type: z.string().trim().min(1, "Action type is required").max(200),
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

  const { type } = parsed.data;
  // Normalize to plain JSON first, so the digest is computed over exactly
  // the value that is stored (and later re-read and re-digested at vote time).
  const payload = toJsonValue(parsed.data.payload);
  const payloadDigest = computeSubjectDigest(type, payload);
  const payloadText = canonicalJson(payload);

  try {
    // Resolve matching ApprovalPolicy
    const policy = await prisma.approvalPolicy.findUnique({
      where: { actionType: type },
    });

    if (!policy) {
      res.status(400).json({ error: `No approval policy configured for action type "${type}"` });
      return;
    }

    // Action, approval request and audit event commit atomically.
    const { action, approvalRequest } = await auditedTransaction(async (tx) => {
      // Raw INSERT with an explicit ::jsonb cast of the canonical text: Prisma
      // 5's Json write path keeps only 16 significant digits of a number, so
      // e.g. a risk score of 0.38331432302637536 would be stored as
      // 0.3833143230263754 -- approvers would then see (and sign) something
      // other than what was requested. Postgres parses the text exactly.
      const newActionId = randomUUID();
      await tx.$executeRaw`
        INSERT INTO "SensitiveAction" ("id", "type", "payload", "payloadDigest", "requestedById")
        VALUES (${newActionId}, ${type}, ${payloadText}::jsonb, ${payloadDigest}, ${req.user!.id})`;
      const newAction = await tx.sensitiveAction.findUniqueOrThrow({ where: { id: newActionId } });
      // Fail closed unless the payload as stored reproduces the digest.
      if (computeSubjectDigest(newAction.type, newAction.payload) !== payloadDigest) {
        throw new Error(`Stored payload for action ${newActionId} does not reproduce its subject digest`);
      }

      const newRequest = await tx.approvalRequest.create({
        data: {
          actionId: newAction.id,
          policyId: policy.id,
          expiresAt: new Date(Date.now() + policy.escalationTimeoutSec * 1000),
        },
      });

      await appendAuditLog(tx, {
        entityType: "SensitiveAction",
        entityId: newAction.id,
        event: "ACTION_CREATED",
        actorId: req.user!.id,
        metadata: {
          type: newAction.type,
          policyId: policy.id,
          approvalRequestId: newRequest.id,
          expiresAt: newRequest.expiresAt,
          payloadDigest,
        },
      });

      return { action: newAction, approvalRequest: newRequest };
    });

    res.status(201).json({
      action: {
        id: action.id,
        type: action.type,
        payload: action.payload,
        payloadDigest: action.payloadDigest,
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

// GET /actions/:id - Retrieve action details, approval request, policy, and votes.
//
// Authorized server-side with the same rule the live Socket.io channel uses
// (server/src/lib/approvalAccess.ts canViewApprovalRecord). A caller without
// a legitimate relationship gets exactly the same 404 as for an id that
// doesn't exist, so the response reveals nothing -- not the payload, votes or
// signatures, and not even whether the action exists.
actionsRouter.get("/:id", requireAuth, async (req: Request, res: Response) => {
  const { id } = req.params;
  const notFound = () => res.status(404).json({ error: "Action not found" });

  try {
    const viewer = await prisma.user.findUnique({ where: { id: req.user!.id }, select: { id: true, role: true } });
    if (!viewer) {
      notFound();
      return;
    }

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

    if (
      !action ||
      !canViewApprovalRecord({
        userId: viewer.id,
        role: viewer.role,
        action,
        policy: action.approvalRequest?.policy ?? null,
        voterIds: action.approvalRequest?.votes.map((v) => v.approverId) ?? [],
      })
    ) {
      notFound();
      return;
    }

    res.json({
      action: {
        id: action.id,
        type: action.type,
        payload: action.payload,
        payloadDigest: action.payloadDigest,
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
          reason: v.reason,
          signature: v.signature,
          signedStatement: v.signedStatement,
          statementHash: v.statementHash,
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
