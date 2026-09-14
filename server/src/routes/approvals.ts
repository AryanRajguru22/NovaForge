import { Router, type Request, type Response } from "express";
import { z } from "zod";
import { generateAuthenticationOptions } from "@simplewebauthn/server";
import type { AuthenticationResponseJSON } from "@simplewebauthn/types";
import { prisma } from "../lib/prisma.js";
import { env } from "../lib/env.js";
import { setChallenge, takeChallenge } from "../lib/challengeStore.js";
import { requireAuth } from "../middleware/requireAuth.js";
import { requireTrust } from "../middleware/requireTrust.js";
import { appendAuditLog, auditedTransaction } from "../lib/audit.js";
import { getApprovalAccessContext } from "../lib/approvalAccess.js";
import { verifyPasskeyAssertion } from "../lib/webauthn.js";
import { sha256Hex } from "../lib/canonicalJson.js";
import {
  DECISIONS,
  buildDecisionStatement,
  computeSubjectDigest,
  parseStatement,
  serializeStatement,
  statementChallenge,
  statementChallengeBytes,
} from "../lib/approvalSignature.js";
import { Prisma, QuorumType } from "@prisma/client";
import { io } from "../app.js";

export const approvalsRouter = Router();

// The findFirst check before the vote transaction below is a fast-path/UX
// check only, not the source of truth -- it's a plain check-then-insert and
// is race-prone under concurrent requests, which can both pass it before
// either commits. ApprovalVote's UNIQUE(requestId, approverId) database
// constraint (see the "add_approval_vote_unique_constraint" migration) is
// the authoritative guard. When a concurrent duplicate slips past the
// findFirst check, it surfaces here as a Postgres unique-violation (Prisma
// P2002), same dual-check pattern server/src/routes/users.ts already uses
// for a different constraint, since Prisma doesn't always surface this as
// P2002 from inside a $transaction -- sometimes only the raw SQLSTATE
// (23505 = unique_violation) is available in the error message.
function isDuplicateVoteError(err: unknown): boolean {
  if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") return true;
  if (err instanceof Error && /\b23505\b/.test(err.message)) return true;
  return false;
}

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

// --- Decision-bound voting (P0-4) ---
//
// 1. POST /approvals/:id/options {decision, reason?}
//    The server builds a canonical decision statement (request, action,
//    subject digest, approver, decision, reason, nonce, validity window) and
//    returns WebAuthn options whose challenge is SHA-256(statement). The
//    statement is also returned so the client can show exactly what is being
//    signed. The pending statement is held server-side, single-use.
// 2. POST /approvals/:id/vote {decision, reason?, response}
//    The server loads the pending statement, requires the submitted decision
//    and reason to equal it, and verifies the assertion against
//    SHA-256(statement) with user verification required. Under the request row
//    lock it re-derives the subject digest from the stored payload and refuses
//    the vote if the subject no longer matches what was signed. The full
//    evidence is stored immutably on the vote.
//
// Consequences: an APPROVE signature can't be submitted as REJECT, a
// signature for request A can't be used on request B, and a signature over
// one payload digest can't approve a modified payload -- each yields a
// different challenge, so the assertion simply doesn't verify.

const decisionSchema = z.enum(DECISIONS);
const reasonSchema = z
  .string()
  .trim()
  .max(500)
  .optional()
  .transform((v) => (v && v.length > 0 ? v : null));

const optionsSchema = z.object({ decision: decisionSchema, reason: reasonSchema });

// Keyed by the challenge itself, so two ceremonies the same approver starts
// for the same request (two tabs, a retry) don't overwrite each other; each
// statement is still single-use, and the one-vote-per-approver database
// constraint decides between them.
function pendingStatementKey(userId: string, requestId: string, challenge: string): string {
  return `vote:${userId}:${requestId}:${challenge}`;
}

/** The challenge an assertion claims to answer, used only to look up the
 * pending statement; verification is always against that statement's own hash. */
function claimedChallenge(response: AuthenticationResponseJSON): string | null {
  try {
    const clientData = JSON.parse(Buffer.from(response.response.clientDataJSON, "base64url").toString("utf8")) as {
      challenge?: unknown;
    };
    return typeof clientData.challenge === "string" && /^[A-Za-z0-9_-]{43}$/.test(clientData.challenge)
      ? clientData.challenge
      : null;
  } catch {
    return null;
  }
}

// POST /approvals/:id/options - Build the decision statement and WebAuthn options for signing it
approvalsRouter.post("/:id/options", requireAuth, async (req: Request, res: Response) => {
  const { id } = req.params;
  const parsed = optionsSchema.safeParse(req.body ?? {});
  if (!parsed.success) {
    res.status(400).json({ error: "A decision (APPROVE, REJECT or POSTPONE) is required", issues: parsed.error.issues });
    return;
  }
  const { decision, reason } = parsed.data;

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
    const optionsAccess = getApprovalAccessContext(user.id, user.role, approvalRequest.action, approvalRequest.policy);
    if (!optionsAccess.isEligibleRole) {
      res.status(403).json({ error: "Forbidden: You are not eligible to approve this action" });
      return;
    }

    if (optionsAccess.isRequester) {
      res.status(403).json({ error: "Forbidden: Requester cannot approve their own action" });
      return;
    }

    const subjectDigest = approvalRequest.action.payloadDigest;
    if (!subjectDigest) {
      // Created before subject digests existed: there is nothing verifiable
      // to sign, so it cannot be decided with a bound signature.
      res.status(409).json({ error: "This request predates signed decisions and cannot be voted on" });
      return;
    }

    const passkeys = user.credentials.filter((c) => c.type === "PASSKEY" && c.credentialId);
    if (passkeys.length === 0) {
      res.status(400).json({ error: "No passkeys registered for this account" });
      return;
    }

    const statement = buildDecisionStatement({
      requestId: approvalRequest.id,
      actionId: approvalRequest.action.id,
      actionType: approvalRequest.action.type,
      subjectDigest,
      approverId: user.id,
      decision,
      reason,
      rpId: env.rpId,
    });
    const serialized = serializeStatement(statement);

    const options = await generateAuthenticationOptions({
      rpID: env.rpId,
      userVerification: "required",
      allowCredentials: passkeys.map((c) => ({ id: c.credentialId! })),
      challenge: statementChallengeBytes(serialized),
    });

    setChallenge(pendingStatementKey(user.id, id, options.challenge), serialized);

    res.json({ ...options, statement: serialized });
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

const voteSchema = z.object({
  decision: decisionSchema,
  reason: reasonSchema,
  response: z.custom<AuthenticationResponseJSON>((v) => typeof v === "object" && v !== null),
});

// POST /approvals/:id/vote - Submit a vote whose signature covers the decision statement
approvalsRouter.post("/:id/vote", requireAuth, requireTrust(), async (req: Request, res: Response) => {
  const { id } = req.params;
  const parsed = voteSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request data", issues: parsed.error.issues });
    return;
  }

  const { decision, reason, response } = parsed.data;

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
    const voteAccess = getApprovalAccessContext(user.id, user.role, approvalRequest.action, approvalRequest.policy);
    if (!voteAccess.isEligibleRole) {
      res.status(403).json({ error: "Forbidden: You are not eligible to approve this action" });
      return;
    }

    if (voteAccess.isRequester) {
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

    // The single-use pending statement this vote must have signed.
    const challenge = claimedChallenge(response);
    const serialized = challenge ? takeChallenge(pendingStatementKey(user.id, id, challenge)) : undefined;
    const statement = serialized ? parseStatement(serialized) : null;
    if (!serialized || !statement || statementChallenge(serialized) !== challenge) {
      res.status(400).json({ error: "Vote session expired or not initialized, please request options again" });
      return;
    }
    if (
      statement.requestId !== id ||
      statement.approverId !== user.id ||
      statement.decision !== decision ||
      statement.reason !== reason
    ) {
      res.status(400).json({ error: "The submitted decision does not match the statement that was signed" });
      return;
    }
    if (new Date(statement.expiresAt) < new Date()) {
      res.status(400).json({ error: "Vote session expired or not initialized, please request options again" });
      return;
    }

    const verification = await verifyPasskeyAssertion({
      credentials: user.credentials,
      response,
      expectedChallenge: statementChallenge(serialized),
      requireUserVerification: true,
    });
    if (!verification.ok) {
      res.status(400).json({
        error: verification.error === "UNKNOWN_CREDENTIAL" ? "Unknown credential" : "Vote verification failed",
      });
      return;
    }
    const credential = verification.credential;
    const statementHash = sha256Hex(serialized);

    // Perform database updates atomically in transaction.
    //
    // Everything read above this point (approvalRequest.status/expiresAt/policy,
    // captured before the transaction even starts) is a fast-path/UX check
    // only. It lets an obviously-invalid request fail fast, but it is NOT
    // authoritative: another concurrent vote transaction (or the escalation
    // poller) can commit a status change, a policy reassignment, or an expiry
    // in the gap between that read and this transaction actually running --
    // and two concurrent votes can each see only their own just-inserted vote
    // under READ COMMITTED. The SELECT ... FOR UPDATE below closes both: it
    // locks this one ApprovalRequest row for the rest of the transaction, so
    // any other transaction trying to read-then-write the same row queues
    // behind this one and observes its effects once it commits.
    //
    // The vote, the resulting status transition and every audit event commit
    // together (P0-5): none of them can exist without the others.
    const txResult = await auditedTransaction(async (tx) => {
      // 1. Lock the ApprovalRequest row FIRST.
      const [lockedRequest] = await tx.$queryRaw<
        { id: string; status: string; expiresAt: Date; policyId: string; actionId: string }[]
      >`SELECT "id", "status", "expiresAt", "policyId", "actionId" FROM "ApprovalRequest" WHERE "id" = ${id} FOR UPDATE`;

      // 2. Re-validate against the locked row, not the pre-transaction read.
      if (!lockedRequest || lockedRequest.status !== "PENDING" || lockedRequest.expiresAt < new Date()) {
        return "NOT_PENDING" as const;
      }

      // 3. The subject being decided must still be exactly what was signed:
      // same action, stored digest unchanged, and the stored payload still
      // hashing to that digest.
      const action = await tx.sensitiveAction.findUnique({ where: { id: lockedRequest.actionId } });
      if (
        !action ||
        action.id !== statement.actionId ||
        action.type !== statement.actionType ||
        action.payloadDigest !== statement.subjectDigest ||
        computeSubjectDigest(action.type, action.payload) !== statement.subjectDigest
      ) {
        return "SUBJECT_MISMATCH" as const;
      }

      // 4. Re-read the policy this request is *currently* assigned to.
      const policy = await tx.approvalPolicy.findUnique({ where: { id: lockedRequest.policyId } });
      if (!policy) {
        throw new Error(
          `ApprovalPolicy ${lockedRequest.policyId} referenced by locked ApprovalRequest ${id} not found`,
        );
      }

      // 4b. Re-check eligibility against the locked action and policy. The
      // pre-transaction check used a snapshot; escalation may have reassigned
      // the request to a fallback policy with different eligible roles since.
      // Must stay before the first write below: a returned sentinel commits.
      const lockedAccess = getApprovalAccessContext(user.id, user.role, action, policy);
      if (!lockedAccess.isEligibleRole) {
        return "NOT_ELIGIBLE" as const;
      }
      if (lockedAccess.isRequester) {
        return "IS_REQUESTER" as const;
      }

      // 5. Update credential counter
      await tx.credential.update({
        where: { id: credential.id },
        data: {
          counter: BigInt(verification.newCounter),
          lastUsedAt: new Date(),
        },
      });

      // 6. Create the vote with its full, re-verifiable evidence.
      const newVote = await tx.approvalVote.create({
        data: {
          requestId: id,
          approverId: user.id,
          decision,
          reason,
          signature: response.response.signature,
          deviceId: credential.id,
          signedStatement: serialized,
          statementHash,
          clientDataJSON: response.response.clientDataJSON,
          authenticatorData: response.response.authenticatorData,
          credentialPublicKey: credential.publicKey,
        },
      });

      // 7. Recalculate status from every vote (row lock held => complete view).
      const votes = await tx.approvalVote.findMany({
        where: { requestId: id },
        include: { approver: true },
      });

      const approvedVotes = votes.filter((v) => v.decision === "APPROVE");
      const rejectedVotes = votes.filter((v) => v.decision === "REJECT");
      const postponedVotes = votes.filter((v) => v.decision === "POSTPONE");

      let updatedStatus: "PENDING" | "APPROVED" | "REJECTED" | "POSTPONED" = "PENDING";

      // REJECT is an immediate veto and takes precedence; POSTPONE likewise
      // ends this request (the requester may submit a new one later).
      if (rejectedVotes.length > 0) {
        updatedStatus = "REJECTED";
      } else if (postponedVotes.length > 0) {
        updatedStatus = "POSTPONED";
      } else {
        if (policy.quorumType === QuorumType.N_OF_M) {
          if (approvedVotes.length >= policy.minApprovals) {
            updatedStatus = "APPROVED";
          }
        } else if (policy.quorumType === QuorumType.ROLE_BASED) {
          const approverRoles = new Set(approvedVotes.map((v) => v.approver.role));
          const allRolesSatisfied = policy.eligibleRoles.every((role) => approverRoles.has(role));
          if (allRolesSatisfied) {
            updatedStatus = "APPROVED";
          }
        } else if (policy.quorumType === QuorumType.WEIGHTED) {
          // For WEIGHTED policies, minApprovals is the weight threshold rather
          // than a headcount -- each approver's User.voteWeight is summed.
          const totalWeight = approvedVotes.reduce((sum, v) => sum + v.approver.voteWeight, 0);
          if (totalWeight >= policy.minApprovals) {
            updatedStatus = "APPROVED";
          }
        }
      }

      await appendAuditLog(tx, {
        entityType: "ApprovalVote",
        entityId: newVote.id,
        event: "VOTE_CAST",
        actorId: user.id,
        metadata: {
          requestId: id,
          decision,
          reason,
          deviceId: credential.id,
          statementHash,
          subjectDigest: statement.subjectDigest,
        },
      });

      // 8. Conditionally transition status -- a compare-and-swap, not a blind
      // write. `transitionWon`, not the locally computed status, is what proves
      // *this* transaction caused the transition.
      let transitionWon = false;
      if (updatedStatus !== "PENDING") {
        const requestUpdate = await tx.approvalRequest.updateMany({
          where: { id, status: "PENDING" },
          data: { status: updatedStatus },
        });
        transitionWon = requestUpdate.count === 1;

        if (transitionWon) {
          const actionUpdate = await tx.sensitiveAction.updateMany({
            where: { id: lockedRequest.actionId, status: "PENDING" },
            data: { status: updatedStatus },
          });
          if (actionUpdate.count !== 1) {
            throw new Error(
              `ApprovalRequest ${id} transitioned to ${updatedStatus} but its SensitiveAction ${lockedRequest.actionId} was not PENDING`,
            );
          }

          await appendAuditLog(tx, {
            entityType: "ApprovalRequest",
            entityId: id,
            event: `REQUEST_${updatedStatus}`,
            actorId: user.id,
            metadata: { decision, reason, voterId: user.id, voteId: newVote.id, statementHash },
          });

          await appendAuditLog(tx, {
            entityType: "SensitiveAction",
            entityId: lockedRequest.actionId,
            event: `ACTION_${updatedStatus}`,
            actorId: user.id,
            metadata: { requestId: id, decision, voteId: newVote.id },
          });
        }
      }

      return {
        vote: newVote,
        requestStatus: updatedStatus,
        transitionWon,
      };
    }).catch((err) => {
      // The vote insert is the only uniquely-constrained write in this
      // transaction (audit seq uniqueness is serialized by the chain-head lock),
      // so a unique violation here means a concurrent duplicate vote.
      if (isDuplicateVoteError(err)) return "DUPLICATE" as const;
      throw err;
    });

    if (txResult === "DUPLICATE") {
      res.status(400).json({ error: "You have already voted on this approval request" });
      return;
    }
    if (txResult === "NOT_PENDING") {
      res.status(400).json({ error: "Approval request is no longer pending" });
      return;
    }
    if (txResult === "NOT_ELIGIBLE") {
      res.status(403).json({ error: "Forbidden: You are not eligible to approve this action" });
      return;
    }
    if (txResult === "IS_REQUESTER") {
      res.status(403).json({ error: "Forbidden: Requester cannot approve their own action" });
      return;
    }
    if (txResult === "SUBJECT_MISMATCH") {
      res.status(409).json({ error: "The request's subject changed after the decision was signed; the vote was not recorded" });
      return;
    }
    const { vote, requestStatus, transitionWon } = txResult;

    // Socket.io event emissions happen only after the transaction committed.
    if (io) {
      io.to(id).emit("vote-cast", { requestId: id, decision, voterId: user.id });
      if (transitionWon) {
        io.to(id).emit("status-update", { requestId: id, status: requestStatus });
      }
    }

    res.json({
      verified: true,
      vote: {
        id: vote.id,
        decision: vote.decision,
        reason: vote.reason,
        statementHash: vote.statementHash,
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
            status: { in: ["APPROVED", "REJECTED", "POSTPONED", "EXPIRED"] },
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

