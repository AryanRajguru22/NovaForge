import { Router, type Request, type Response } from "express";
import { z } from "zod";
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import type { AuthenticationResponseJSON } from "@simplewebauthn/types";
import { isoBase64URL } from "@simplewebauthn/server/helpers";
import { prisma } from "../lib/prisma.js";
import { env } from "../lib/env.js";
import { setChallenge, takeChallenge } from "../lib/challengeStore.js";
import { requireAuth } from "../middleware/requireAuth.js";
import { appendAuditLog } from "../lib/audit.js";
import { QuorumType } from "@prisma/client";
import { io } from "../app.js";

export const approvalsRouter = Router();

// GET /approvals/pending - Return pending approval requests eligible for the authenticated user
approvalsRouter.get("/pending", requireAuth, async (req: Request, res: Response) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.user!.id } });
    if (!user) {
      res.status(404).json({ error: "User not found" });
      return;
    }

    const pendingRequests = await prisma.approvalRequest.findMany({
      where: {
        status: "PENDING",
        expiresAt: { gt: new Date() },
        policy: {
          eligibleRoles: { has: user.role },
        },
        action: {
          requestedById: { not: user.id },
        },
        votes: {
          none: {
            approverId: user.id,
          },
        },
      },
      include: {
        action: {
          include: {
            requestedBy: {
              select: { id: true, email: true, name: true, role: true },
            },
          },
        },
        policy: true,
        votes: {
          include: {
            approver: {
              select: { id: true, email: true, name: true, role: true },
            },
          },
        },
      },
    });

    res.json(pendingRequests);
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// POST /approvals/:id/options - Generate WebAuthn options for voting
approvalsRouter.post("/:id/options", requireAuth, async (req: Request, res: Response) => {
  const { id } = req.params;

  try {
    const approvalRequest = await prisma.approvalRequest.findUnique({
      where: { id },
      include: {
        action: true,
        policy: true,
      },
    });

    if (!approvalRequest) {
      res.status(404).json({ error: "Approval request not found" });
      return;
    }

    if (approvalRequest.status !== "PENDING" || approvalRequest.expiresAt < new Date()) {
      res.status(400).json({ error: "Approval request is no longer pending" });
      return;
    }

    const user = await prisma.user.findUnique({
      where: { id: req.user!.id },
      include: { credentials: true },
    });

    if (!user) {
      res.status(404).json({ error: "User not found" });
      return;
    }

    // Check eligibility
    if (!approvalRequest.policy.eligibleRoles.includes(user.role)) {
      res.status(403).json({ error: "Forbidden: You are not eligible to approve this action" });
      return;
    }

    if (approvalRequest.action.requestedById === user.id) {
      res.status(403).json({ error: "Forbidden: Requester cannot approve their own action" });
      return;
    }

    const passkeys = user.credentials.filter((c) => c.type === "PASSKEY" && c.credentialId);
    if (passkeys.length === 0) {
      res.status(400).json({ error: "No passkeys registered for this account" });
      return;
    }

    const options = await generateAuthenticationOptions({
      rpID: env.rpId,
      userVerification: "preferred",
      allowCredentials: passkeys.map((c) => ({ id: c.credentialId! })),
    });

    // Save the challenge in challenge store
    setChallenge(`vote:${user.id}:${id}`, options.challenge);

    res.json(options);
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

const voteSchema = z.object({
  decision: z.enum(["APPROVE", "REJECT"]),
  response: z.custom<AuthenticationResponseJSON>((v) => typeof v === "object" && v !== null),
});

// POST /approvals/:id/vote - Submit approval vote with WebAuthn signature
approvalsRouter.post("/:id/vote", requireAuth, async (req: Request, res: Response) => {
  const { id } = req.params;
  const parsed = voteSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request data", issues: parsed.error.issues });
    return;
  }

  const { decision, response } = parsed.data;

  try {
    const approvalRequest = await prisma.approvalRequest.findUnique({
      where: { id },
      include: {
        action: true,
        policy: true,
      },
    });

    if (!approvalRequest) {
      res.status(404).json({ error: "Approval request not found" });
      return;
    }

    if (approvalRequest.status !== "PENDING" || approvalRequest.expiresAt < new Date()) {
      res.status(400).json({ error: "Approval request is no longer pending" });
      return;
    }

    const user = await prisma.user.findUnique({
      where: { id: req.user!.id },
      include: { credentials: true },
    });

    if (!user) {
      res.status(404).json({ error: "User not found" });
      return;
    }

    // Eligibility check
    if (!approvalRequest.policy.eligibleRoles.includes(user.role)) {
      res.status(403).json({ error: "Forbidden: You are not eligible to approve this action" });
      return;
    }

    if (approvalRequest.action.requestedById === user.id) {
      res.status(403).json({ error: "Forbidden: Requester cannot approve their own action" });
      return;
    }

    // Check duplicate vote
    const existingVote = await prisma.approvalVote.findFirst({
      where: { requestId: id, approverId: user.id },
    });
    if (existingVote) {
      res.status(400).json({ error: "You have already voted on this approval request" });
      return;
    }

    // Get expected challenge
    const expectedChallenge = takeChallenge(`vote:${user.id}:${id}`);
    if (!expectedChallenge) {
      res.status(400).json({ error: "Vote session expired or not initialized, please request options again" });
      return;
    }

    // Find signer passkey
    const credential = user.credentials.find(
      (c) => c.type === "PASSKEY" && c.credentialId === response.id,
    );
    if (!credential || !credential.publicKey || !credential.credentialId) {
      res.status(400).json({ error: "Unknown credential" });
      return;
    }

    // Verify assertion
    // Real WebAuthn assertions can't be scripted without a live authenticator, so the
    // test suite substitutes a mock verification result — gated on NODE_ENV=test as well
    // as the flag itself, so this can never bypass signature checks outside a test run.
    let verification;
    try {
      if (process.env.NODE_ENV === "test" && process.env.BYPASS_WEBAUTHN === "true") {
        verification = {
          verified: true,
          authenticationInfo: {
            newCounter: Number(credential.counter) + 1,
          },
        };
      } else {
        verification = await verifyAuthenticationResponse({
          response,
          expectedChallenge,
          expectedOrigin: env.rpOrigin,
          expectedRPID: env.rpId,
          authenticator: {
            credentialID: credential.credentialId,
            credentialPublicKey: isoBase64URL.toBuffer(credential.publicKey),
            counter: Number(credential.counter),
          },
        });
      }
    } catch (err) {
      res.status(400).json({ error: "Vote verification failed" });
      return;
    }

    if (!verification.verified) {
      res.status(400).json({ error: "Vote verification failed" });
      return;
    }

    // Perform database updates atomically in transaction
    const { vote, requestStatus, actionStatus } = await prisma.$transaction(async (tx) => {
      // 1. Update credential counter
      await tx.credential.update({
        where: { id: credential.id },
        data: {
          counter: BigInt(verification.authenticationInfo.newCounter),
          lastUsedAt: new Date(),
        },
      });

      // 2. Create the Vote
      const newVote = await tx.approvalVote.create({
        data: {
          requestId: id,
          approverId: user.id,
          decision,
          signature: response.response.signature,
          deviceId: credential.id,
        },
      });

      // 3. Retrieve all votes for this request to recalculate status
      const votes = await tx.approvalVote.findMany({
        where: { requestId: id },
        include: { approver: true },
      });

      const approvedVotes = votes.filter((v) => v.decision === "APPROVE");
      const rejectedVotes = votes.filter((v) => v.decision === "REJECT");

      let updatedStatus: "PENDING" | "APPROVED" | "REJECTED" = "PENDING";

      if (rejectedVotes.length > 0) {
        updatedStatus = "REJECTED";
      } else {
        if (approvalRequest.policy.quorumType === QuorumType.N_OF_M) {
          if (approvedVotes.length >= approvalRequest.policy.minApprovals) {
            updatedStatus = "APPROVED";
          }
        } else if (approvalRequest.policy.quorumType === QuorumType.ROLE_BASED) {
          const approverRoles = new Set(approvedVotes.map((v) => v.approver.role));
          const allRolesSatisfied = approvalRequest.policy.eligibleRoles.every((role) =>
            approverRoles.has(role),
          );
          if (allRolesSatisfied) {
            updatedStatus = "APPROVED";
          }
        } else if (approvalRequest.policy.quorumType === QuorumType.WEIGHTED) {
          // TODO: Implement WEIGHTED quorum once schema weights are supported
        }
      }

      // 4. Update status if changed
      if (updatedStatus !== "PENDING") {
        await tx.approvalRequest.update({
          where: { id },
          data: { status: updatedStatus },
        });

        await tx.sensitiveAction.update({
          where: { id: approvalRequest.actionId },
          data: { status: updatedStatus },
        });
      }

      return { vote: newVote, requestStatus: updatedStatus, actionStatus: updatedStatus };
    });

    // 5. Append audit logs (outside transaction)
    await appendAuditLog({
      entityType: "ApprovalVote",
      entityId: vote.id,
      event: "VOTE_CAST",
      actorId: user.id,
      metadata: {
        requestId: id,
        decision,
        deviceId: credential.id,
      },
    });

    if (requestStatus !== "PENDING") {
      await appendAuditLog({
        entityType: "ApprovalRequest",
        entityId: id,
        event: requestStatus === "APPROVED" ? "REQUEST_APPROVED" : "REQUEST_REJECTED",
        actorId: user.id,
        metadata: {
          decision,
          voterId: user.id,
        },
      });

      await appendAuditLog({
        entityType: "SensitiveAction",
        entityId: approvalRequest.actionId,
        event: actionStatus === "APPROVED" ? "ACTION_APPROVED" : "ACTION_REJECTED",
        actorId: user.id,
        metadata: {
          requestId: id,
          decision,
        },
      });
    }

    // 6. Socket.io event emissions
    if (io) {
      io.to(id).emit("vote-cast", { requestId: id, decision, voterId: user.id });
      if (requestStatus !== "PENDING") {
        io.to(id).emit("status-update", { requestId: id, status: requestStatus });
      }
    }

    res.json({
      verified: true,
      vote: {
        id: vote.id,
        decision: vote.decision,
        timestamp: vote.timestamp,
      },
      requestStatus,
    });
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /approvals/history - Return history of approval requests (voted on by user or completed)
approvalsRouter.get("/history", requireAuth, async (req: Request, res: Response) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.user!.id } });
    if (!user) {
      res.status(404).json({ error: "User not found" });
      return;
    }

    const history = await prisma.approvalRequest.findMany({
      where: {
        OR: [
          // User voted on it
          {
            votes: {
              some: {
                approverId: user.id,
              },
            },
          },
          // Completed requests where user was an eligible approver
          {
            status: { in: ["APPROVED", "REJECTED", "EXPIRED"] },
            policy: {
              eligibleRoles: { has: user.role },
            },
          },
        ],
      },
      include: {
        action: {
          include: {
            requestedBy: {
              select: { id: true, email: true, name: true, role: true },
            },
          },
        },
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
      orderBy: { expiresAt: "desc" },
    });

    res.json(history);
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

