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
