import { prisma } from "./prisma.js";
import { appendAuditLog, auditedTransaction } from "./audit.js";

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
        policy: true,
      },
    });

    for (const request of expiredRequests) {
      const { id, policy, actionId } = request;

      if (policy.fallbackPolicyId) {
        // Resolve fallback policy
        const fallbackPolicy = await prisma.approvalPolicy.findUnique({
          where: { id: policy.fallbackPolicyId },
        });

        if (fallbackPolicy) {
          const newExpiresAt = new Date(Date.now() + fallbackPolicy.escalationTimeoutSec * 1000);

          // The reassignment and its audit events commit together or not at all.
          const success = await auditedTransaction(async (tx) => {
            const updated = await tx.approvalRequest.updateMany({
              where: {
                id,
                status: "PENDING",
              },
              data: {
                policyId: fallbackPolicy.id,
                expiresAt: newExpiresAt,
              },
            });
            if (updated.count !== 1) return false;

            await appendAuditLog(tx, {
              entityType: "ApprovalRequest",
              entityId: id,
              event: "ESCALATION_TRIGGERED",
              metadata: {
                previousPolicyId: policy.id,
                fallbackPolicyId: fallbackPolicy.id,
              },
            });

            await appendAuditLog(tx, {
              entityType: "ApprovalRequest",
              entityId: id,
              event: "FALLBACK_POLICY_ASSIGNED",
              metadata: {
                fallbackPolicyId: fallbackPolicy.id,
                expiresAt: newExpiresAt,
              },
            });
            return true;
          });

          if (!success) {
            console.log(`Request ${id} is no longer PENDING. Skipping escalation.`);
            continue;
          }

          // Socket event
          if (ioInstance) {
            ioInstance.to(id).emit("escalated", {
              requestId: id,
              newPolicyId: fallbackPolicy.id,
              expiresAt: newExpiresAt,
            });
          }
          console.log(`Escalated request ${id} to policy ${fallbackPolicy.id}`);
        } else {
          // Fallback policy defined but does not exist in DB (invalid configuration)
          console.error(`Fallback policy ${policy.fallbackPolicyId} for request ${id} not found in DB. Expiring request.`);
          await expireRequest(id, actionId);
        }
      } else {
        // No fallback policy, transition to EXPIRED
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
