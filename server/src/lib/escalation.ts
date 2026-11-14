import { prisma } from "./prisma.js";
import { appendAuditLog, auditedTransaction } from "./audit.js";
import { effectiveLevel, nextLevel } from "./policySnapshot.js";

let ioInstance: any = null;
let intervalHandle: NodeJS.Timeout | null = null;

export function initEscalationService(io: any) {
  ioInstance = io;
  // Start the interval timer
  const intervalMs = 5000; // Check every 5 seconds for responsive testing / demo
  intervalHandle = setInterval(checkEscalations, intervalMs);
  intervalHandle.unref(); // Prevent blocking process termination
  console.log(`Escalation service started (interval: ${intervalMs}ms)`);
}

/** Stops the polling interval — used by tests so one file's timer doesn't keep
 * firing (and racing appendAuditLog) once the next test file has moved on. */
export function stopEscalationService() {
  if (intervalHandle) {
    clearInterval(intervalHandle);
    intervalHandle = null;
  }
}

let isRunning = false;

// Exported only so tests can invoke a single escalation pass directly and
// deterministically (e.g. concurrently with a vote, via Promise.all) instead
// of waiting on the real 5-second setInterval in initEscalationService above.
// Production behavior is unchanged -- this is still the exact same function
// the interval timer calls; exporting it adds a second caller, nothing else.
export async function checkEscalations() {
  if (isRunning) return;
  isRunning = true;
  try {
    const expiredRequests = await prisma.approvalRequest.findMany({
      where: {
        status: "PENDING",
        expiresAt: { lte: new Date() },
      },
      include: {
        policyLevels: { orderBy: { level: "asc" } },
      },
    });

    for (const request of expiredRequests) {
      const { id, actionId } = request;

      // Escalation follows the policy chain frozen at creation
      // (server/src/lib/policySnapshot.ts), never the live policies: the next
      // level is the fallback as it was when the request was made, with its
      // own timeout. The level only ever increases and the chain is finite
      // (at most MAX_ESCALATIONS + 1 levels), so escalation always
      // terminates; a request on its last level -- or one whose snapshot is
      // missing -- expires (fail closed).
      const current = effectiveLevel(request);
      const next = current ? nextLevel(request) : null;

      if (current && next) {
        const newExpiresAt = new Date(Date.now() + next.escalationTimeoutSec * 1000);

        // The reassignment and its audit events commit together or not at all.
        // The level and expiry are part of the compare-and-swap, so a request
        // that another pass or a vote already moved is skipped.
        const success = await auditedTransaction(async (tx) => {
          const updated = await tx.approvalRequest.updateMany({
            where: {
              id,
              status: "PENDING",
              escalationLevel: current.level,
              expiresAt: { lte: new Date() },
            },
            data: {
              escalationLevel: next.level,
              policyId: next.policyId,
              expiresAt: newExpiresAt,
            },
          });
          if (updated.count !== 1) return false;

          await appendAuditLog(tx, {
            entityType: "ApprovalRequest",
            entityId: id,
            event: "ESCALATION_TRIGGERED",
            metadata: {
              previousPolicyId: current.policyId,
              fallbackPolicyId: next.policyId,
              fromLevel: current.level,
              toLevel: next.level,
              levelCount: request.policyLevels.length,
            },
          });

          await appendAuditLog(tx, {
            entityType: "ApprovalRequest",
            entityId: id,
            event: "FALLBACK_POLICY_ASSIGNED",
            metadata: {
              fallbackPolicyId: next.policyId,
              expiresAt: newExpiresAt,
            },
          });
          return true;
        });

        if (!success) {
          console.log(`Request ${id} is no longer PENDING at level ${current.level}. Skipping escalation.`);
          continue;
        }

        // Socket event
        if (ioInstance) {
          ioInstance.to(id).emit("escalated", {
            requestId: id,
            newPolicyId: next.policyId,
            expiresAt: newExpiresAt,
          });
        }
        console.log(`Escalated request ${id} to level ${next.level} (policy ${next.policyId})`);
      } else {
        // Last level (or no snapshot): transition to EXPIRED
        await expireRequest(id, actionId);
      }
    }
  } catch (error) {
    console.error("Error running escalation check:", error);
  } finally {
    isRunning = false;
  }
}

async function expireRequest(requestId: string, actionId: string) {
  const success = await auditedTransaction(async (tx) => {
    const updated = await tx.approvalRequest.updateMany({
      where: {
        id: requestId,
        status: "PENDING",
      },
      data: { status: "EXPIRED" },
    });
    if (updated.count !== 1) return false;
    await tx.sensitiveAction.updateMany({
      where: {
        id: actionId,
        status: "PENDING",
      },
      data: { status: "EXPIRED" },
    });
    await appendAuditLog(tx, {
      entityType: "ApprovalRequest",
      entityId: requestId,
      event: "REQUEST_EXPIRED",
    });
    await appendAuditLog(tx, {
      entityType: "SensitiveAction",
      entityId: actionId,
      event: "ACTION_EXPIRED",
    });
    return true;
  });

  if (!success) {
    console.log(`Request ${requestId} is no longer PENDING. Skipping expiration.`);
    return;
  }

  if (ioInstance) {
    ioInstance.to(requestId).emit("status-update", {
      requestId,
      status: "EXPIRED",
    });
  }
  console.log(`Expired request ${requestId} and action ${actionId}`);
}
