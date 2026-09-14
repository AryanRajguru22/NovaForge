import type { Role } from "@prisma/client";

// The two raw, database-derived facts that determine whether a given user
// has any legitimate relationship to a given ApprovalRequest -- extracted
// once so REST (server/src/routes/approvals.ts) and the Socket.io join
// authorization (server/src/lib/socketSecurity.ts) never maintain two
// independent, potentially-drifting copies of "is this the requester" / "is
// this role eligible under this policy". The two callers combine these facts
// differently on purpose: REST's vote-eligibility check excludes the
// requester (eligible role AND NOT the requester), while the socket layer's
// watch-authorization includes them (the requester OR an eligible role) --
// that's a genuine difference in what each question is asking, not
// duplicated logic, so this deliberately returns the raw facts rather than a
// single combined boolean.
export interface ApprovalAccessContext {
  isRequester: boolean;
  isEligibleRole: boolean;
}

/**
 * Who may see an action's details (payload, votes, signatures) or subscribe
 * to its live events. Legitimate relationships only:
 *   - the requester,
 *   - a user whose role is eligible under the request's current policy
 *     (they may be asked to decide it),
 *   - a user who already voted on it,
 *   - SUPER_ADMIN, the audit authority.
 * ADMIN manages policies but does not get blanket read access to payloads.
 * Status is checked separately by session liveness; callers must pass the
 * live, database-read role, never a token claim.
 */
export function canViewApprovalRecord(input: {
  userId: string;
  role: Role;
  action: { requestedById: string };
  policy: { eligibleRoles: Role[] } | null;
  voterIds: string[];
}): boolean {
  if (input.role === "SUPER_ADMIN") return true;
  if (input.userId === input.action.requestedById) return true;
  if (input.policy && input.policy.eligibleRoles.includes(input.role)) return true;
  return input.voterIds.includes(input.userId);
}

export function getApprovalAccessContext(
  userId: string,
  role: Role,
  action: { requestedById: string },
  policy: { eligibleRoles: Role[] },
): ApprovalAccessContext {
  return {
    isRequester: userId === action.requestedById,
    isEligibleRole: policy.eligibleRoles.includes(role),
  };
}
