import { prisma } from "./prisma.js";
import { appendAuditLog } from "./audit.js";

let ioInstance: any = null;

export function initEscalationService(io: any) {
  ioInstance = io;
  // Start the interval timer
  const intervalMs = 5000; // Check every 5 seconds for responsive testing / demo
  const interval = setInterval(checkEscalations, intervalMs);
  interval.unref(); // Prevent blocking process termination
  console.log(`Escalation service started (interval: ${intervalMs}ms)`);
}

let isRunning = false;

async function checkEscalations() {
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

          let success = false;
          await prisma.$transaction(async (tx) => {
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
            success = updated.count === 1;
          });

          if (!success) {
            console.log(`Request ${id} is no longer PENDING. Skipping escalation.`);
            continue;
          }

          // Audit logs
          await appendAuditLog({
            entityType: "ApprovalRequest",
            entityId: id,
            event: "ESCALATION_TRIGGERED",
            metadata: {
              previousPolicyId: policy.id,
              fallbackPolicyId: fallbackPolicy.id,
            },
          });

          await appendAuditLog({
            entityType: "ApprovalRequest",
            entityId: id,
            event: "FALLBACK_POLICY_ASSIGNED",
            metadata: {
              fallbackPolicyId: fallbackPolicy.id,
              expiresAt: newExpiresAt,
            },
          });

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
  let success = false;
  await prisma.$transaction(async (tx) => {
    const updated = await tx.approvalRequest.updateMany({
      where: {
        id: requestId,
        status: "PENDING",
      },
      data: { status: "EXPIRED" },
    });
    if (updated.count === 1) {
      await tx.sensitiveAction.updateMany({
        where: {
          id: actionId,
          status: "PENDING",
        },
        data: { status: "EXPIRED" },
      });
      success = true;
    }
  });

  if (!success) {
    console.log(`Request ${requestId} is no longer PENDING. Skipping expiration.`);
    return;
  }

  await appendAuditLog({
    entityType: "ApprovalRequest",
    entityId: requestId,
    event: "REQUEST_EXPIRED",
  });

  await appendAuditLog({
    entityType: "SensitiveAction",
    entityId: actionId,
    event: "ACTION_EXPIRED",
  });

  if (ioInstance) {
    ioInstance.to(requestId).emit("status-update", {
      requestId,
      status: "EXPIRED",
    });
  }
  console.log(`Expired request ${requestId} and action ${actionId}`);
}
