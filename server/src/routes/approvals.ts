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
import { requireTrust } from "../middleware/requireTrust.js";
import { appendAuditLog } from "../lib/audit.js";
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
approvalsRouter.post("/:id/vote", requireAuth, requireTrust(), async (req: Request, res: Response) => {
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

    // Perform database updates atomically in transaction.
    //
    // Everything read above this point (approvalRequest.status/expiresAt/policy,
    // captured before the transaction even starts) is a fast-path/UX check
    // only -- exactly like the findFirst duplicate-vote check a few lines up.
    // It lets an obviously-invalid request fail fast, before ever prompting
    // for a WebAuthn signature, but it is NOT authoritative: another
    // concurrent vote transaction (or the escalation poller) can commit a
    // status change, a policy reassignment, or an expiry in the gap between
    // that read and this transaction actually running -- and, separately,
    // two concurrent votes can each see only their own just-inserted vote
    // (the other's insert is still uncommitted and invisible under Postgres's
    // default READ COMMITTED isolation), so a plain re-tally without locking
    // can compute an incomplete quorum, and a plain unconditional status
    // write can blindly overwrite whatever another such transaction just
    // committed. The SELECT ... FOR UPDATE below closes both: it locks this
    // one ApprovalRequest row for the rest of the transaction, so any other
    // transaction trying to read-then-write the same row (another vote, or
    // escalation's own conditional updateMany) queues behind this one and is
    // guaranteed to observe this transaction's effects once it commits.
    // Locking one row at a time means votes on *different* requests are never
    // serialized against each other -- only concurrent writers to the same
    // request queue up, and the queued writer waits rather than retrying.
    const txResult = await prisma.$transaction(async (tx) => {
      // 1. Lock the ApprovalRequest row FIRST -- before any write, and before
      // re-reading anything else the decision below depends on. Prisma has no
      // native "lock this row" option on its fluent API, so a raw query
      // (auto-parameterized via the tagged-template form, not
      // $queryRawUnsafe) is the standard way to issue FOR UPDATE through the
      // transaction-bound client. The values read here -- not the outer,
      // pre-transaction read -- are what the rest of this transaction treats
      // as authoritative.
      const [lockedRequest] = await tx.$queryRaw<
        { id: string; status: string; expiresAt: Date; policyId: string; actionId: string }[]
      >`SELECT "id", "status", "expiresAt", "policyId", "actionId" FROM "ApprovalRequest" WHERE "id" = ${id} FOR UPDATE`;

      // 2. Re-validate against the locked row, not the pre-transaction read.
      // A concurrent transaction may already have resolved, rejected, or
      // expired this request in the gap between the outer read and this lock
      // being acquired -- if so, no vote is inserted and nothing about this
      // request (ApprovalRequest or SensitiveAction) is touched.
      if (!lockedRequest || lockedRequest.status !== "PENDING" || lockedRequest.expiresAt < new Date()) {
        return "NOT_PENDING" as const;
      }

      // 3. Re-read the policy this request is *currently* assigned to (its
      // policyId, as just read under the lock), not the policy object
      // captured by the outer, pre-transaction read -- if escalation
      // reassigned this request to a fallback policy concurrently, the
      // quorum rules applied below must match the row's real, current
      // policyId, not a stale one.
      const policy = await tx.approvalPolicy.findUnique({ where: { id: lockedRequest.policyId } });
      if (!policy) {
        // ApprovalRequest.policyId is a required, RESTRICT-protected foreign
        // key -- a policy can never be deleted while a request still
        // references it (server/src/routes/policies.ts). Reaching this is a
        // data-integrity violation, not a normal "policy went away" case, so
        // it fails loud via the outer 500 handler rather than guessing.
        throw new Error(
          `ApprovalPolicy ${lockedRequest.policyId} referenced by locked ApprovalRequest ${id} not found`,
        );
      }

      // 4. Update credential counter
      await tx.credential.update({
        where: { id: credential.id },
        data: {
          counter: BigInt(verification.authenticationInfo.newCounter),
          lastUsedAt: new Date(),
        },
      });

      // 5. Create the Vote
      const newVote = await tx.approvalVote.create({
        data: {
          requestId: id,
          approverId: user.id,
          decision,
          signature: response.response.signature,
          deviceId: credential.id,
        },
      });

      // 6. Retrieve all votes for this request to recalculate status. Because
      // the row lock from step 1 is held for the rest of this transaction, no
      // other vote transaction for this same request can be concurrently in
      // flight -- this read is guaranteed to see every vote already
      // committed for this request, so the tally below can't miss a
      // just-inserted-but-not-yet-committed vote from a competing approver.
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
          // than a headcount -- each approver's User.voteWeight (settable per
          // account by a super admin) is summed instead of just counting votes.
          const totalWeight = approvedVotes.reduce((sum, v) => sum + v.approver.voteWeight, 0);
          if (totalWeight >= policy.minApprovals) {
            updatedStatus = "APPROVED";
          }
        }
      }

      // 7. Conditionally transition status -- a compare-and-swap, not a
      // blind write. The WHERE clause only matches if the row is still
      // PENDING at the moment this statement executes. Under the lock held
      // since step 1, nothing else could have changed it in between, so this
      // is expected to always match (count === 1) whenever
      // updatedStatus !== "PENDING" -- the guard is kept anyway, both as
      // defense-in-depth against a future change to this transaction's lock
      // discipline, and to mirror the exact pattern
      // server/src/lib/escalation.ts already uses for its own conditional
      // writes. `transitionWon` -- not the locally computed `updatedStatus`
      // -- is what the rest of this handler treats as proof that *this*
      // transaction actually caused the transition: under concurrent votes,
      // more than one transaction can independently compute the same (or a
      // conflicting) terminal status, but only the one whose conditional
      // update actually matched a row still in PENDING gets to record it.
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
            // ApprovalRequest just transitioned under this same lock, so its
            // linked SensitiveAction must still have been PENDING too --
            // anything else means the two drifted out of sync via some other
            // code path, which must never be allowed to pass silently.
            throw new Error(
              `ApprovalRequest ${id} transitioned to ${updatedStatus} but its SensitiveAction ${lockedRequest.actionId} was not PENDING`,
            );
          }
        }
      }

      return {
        vote: newVote,
        requestStatus: updatedStatus,
        actionStatus: updatedStatus,
        actionId: lockedRequest.actionId,
        transitionWon,
      };
    }).catch((err) => {
      // isDuplicateVoteError() is being applied to this specific transaction,
      // and treats ANY P2002/23505 it sees here as a duplicate vote. That is
      // only correct because, as this transaction is currently written, the
      // vote insert (tx.approvalVote.create above) is the sole
      // uniquely-constrained write in it -- every other statement
      // (tx.$queryRaw ... FOR UPDATE, tx.approvalPolicy.findUnique,
      // tx.credential.update, tx.approvalRequest.updateMany,
      // tx.sensitiveAction.updateMany) is either a plain read or writes by
      // primary key/conditional-WHERE and touches no unique field, so none of
      // them can raise P2002/23505. If a future change adds another
      // uniquely-constrained write inside this transaction, this catch must
      // be tightened to identify the specific ApprovalVote unique constraint
      // (e.g. by inspecting err.meta?.target) rather than treating every
      // P2002/23505 here as "already voted" -- otherwise an unrelated
      // constraint violation would be silently misreported to the caller as
      // a duplicate vote.
      if (isDuplicateVoteError(err)) return "DUPLICATE" as const;
      throw err;
    });

    if (txResult === "DUPLICATE") {
      res.status(400).json({ error: "You have already voted on this approval request" });
      return;
    }
    if (txResult === "NOT_PENDING") {
      // Reached only when the locked, in-transaction re-check (not the
      // earlier fast-path read) found the request already resolved/expired --
      // same response the fast-path check above would have given, just
      // arrived at authoritatively instead of optimistically.
      res.status(400).json({ error: "Approval request is no longer pending" });
      return;
    }
    const { vote, requestStatus, actionStatus, actionId, transitionWon } = txResult;

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

    // Terminal audit events are appended only when THIS transaction's
    // conditional write actually caused the transition (transitionWon), not
    // merely when this transaction's own local tally happened to compute a
    // terminal status -- see the comment on `transitionWon` above. This is
    // what stops concurrent votes from each independently appending their own
    // REQUEST_*/ACTION_* audit rows for what is really a single transition.
    if (transitionWon) {
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
        entityId: actionId,
        event: actionStatus === "APPROVED" ? "ACTION_APPROVED" : "ACTION_REJECTED",
        actorId: user.id,
        metadata: {
          requestId: id,
          decision,
        },
      });
    }

    // 6. Socket.io event emissions. vote-cast always fires (a vote really was
    // recorded); the terminal status-update, like the terminal audit events
    // above, fires only when this transaction actually caused the
    // transition, so competing transactions never emit duplicate or
    // contradictory terminal events for the same request.
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

