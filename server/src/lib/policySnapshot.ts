import type { Prisma, QuorumType, Role } from "@prisma/client";

// Immutable per-request governing policy (Phase 1).
//
// When an ApprovalRequest is created, the policy matched for its action type
// AND its whole fallback chain are copied into ApprovalRequestPolicyLevel rows
// in the same transaction. From then on every decision about the request --
// who may vote, how votes are tallied, when and where it escalates -- reads
// those rows and never the live ApprovalPolicy. Editing or deleting a policy
// affects only requests created afterwards.
//
// Fallback semantics: level n+1 is the fallback of level n as it was at
// creation. Escalation moves the request from its current level to the next
// pre-captured one (ApprovalRequest.escalationLevel + 1), with that level's
// own escalation timeout. Votes already cast carry over and are re-evaluated
// under the new level's rules (unchanged behaviour). The chain is finite and
// the level only ever increases, so escalation always terminates: after the
// last level the request expires (fail closed).

/** Maximum number of escalations; a chain therefore has at most 6 levels. */
export const MAX_ESCALATIONS = 5;

/**
 * A user who authored the captured revision of a governing policy, or any
 * revision of it in this window before capture, may not vote on requests
 * governed by it.
 */
export const POLICY_EDIT_COOLING_OFF_MS = 24 * 60 * 60 * 1000;

/** pg_advisory_xact_lock key serialising writers of the policy fallback graph.
 * Must match the key used by novaforge_policy_fallback_guard(). */
export const POLICY_GRAPH_LOCK_KEY = 727001;

export interface PolicyLevelDraft {
  level: number;
  policyId: string;
  actionType: string;
  quorumType: QuorumType;
  minApprovals: number;
  eligibleRoles: Role[];
  escalationTimeoutSec: number;
  policyRevisionId: string | null;
  conflictedUserIds: string[];
}

interface LockedPolicyRow {
  id: string;
  actionType: string;
  quorumType: QuorumType;
  minApprovals: number;
  eligibleRoles: Role[];
  fallbackPolicyId: string | null;
  escalationTimeoutSec: number;
}

/**
 * Reads the policy chain rooted at `rootPolicyId` under FOR SHARE row locks
 * (policy writers take FOR UPDATE, so each policy is read either entirely
 * before or entirely after any concurrent edit) and returns the levels to
 * persist. A missing fallback, a revisit (cycle in legacy data) or reaching
 * MAX_ESCALATIONS simply ends the chain: the request then expires after its
 * last level rather than escalating forever.
 */
export async function captureGoverningPolicy(
  tx: Prisma.TransactionClient,
  rootPolicyId: string,
  now: Date = new Date(),
): Promise<{ levels: PolicyLevelDraft[]; truncated: boolean }> {
  const levels: PolicyLevelDraft[] = [];
  const seen = new Set<string>();
  let nextId: string | null = rootPolicyId;
  let truncated = false;

  while (nextId) {
    if (seen.has(nextId) || levels.length > MAX_ESCALATIONS) {
      truncated = true;
      break;
    }
    seen.add(nextId);

    const rows: LockedPolicyRow[] = await tx.$queryRaw<LockedPolicyRow[]>`
      SELECT "id", "actionType", "quorumType"::text AS "quorumType", "minApprovals",
             "eligibleRoles"::text[] AS "eligibleRoles", "fallbackPolicyId", "escalationTimeoutSec"
      FROM "ApprovalPolicy" WHERE "id" = ${nextId} FOR SHARE`;
    const row: LockedPolicyRow | undefined = rows[0];
    if (!row) {
      // The root must exist; a dangling fallback just ends the chain.
      if (levels.length === 0) throw new Error(`ApprovalPolicy ${nextId} not found`);
      break;
    }

    // Revisions are written in the editor's transaction, which holds the
    // policy row FOR UPDATE; our FOR SHARE above therefore sees all of them.
    const latest = await tx.approvalPolicyRevision.findFirst({
      where: { policyId: row.id },
      orderBy: { version: "desc" },
    });
    const recent = await tx.approvalPolicyRevision.findMany({
      where: { policyId: row.id, createdAt: { gte: new Date(now.getTime() - POLICY_EDIT_COOLING_OFF_MS) } },
      select: { changedById: true },
    });
    const conflicted = new Set<string>();
    if (latest?.changedById) conflicted.add(latest.changedById);
    for (const r of recent) if (r.changedById) conflicted.add(r.changedById);

    levels.push({
      level: levels.length,
      policyId: row.id,
      actionType: row.actionType,
      quorumType: row.quorumType,
      minApprovals: row.minApprovals,
      eligibleRoles: row.eligibleRoles,
      escalationTimeoutSec: row.escalationTimeoutSec,
      policyRevisionId: latest?.id ?? null,
      conflictedUserIds: [...conflicted].sort(),
    });
    nextId = row.fallbackPolicyId;
  }

  return { levels, truncated };
}

export interface SnapshotLevel {
  level: number;
  policyId: string;
  actionType: string;
  quorumType: QuorumType;
  minApprovals: number;
  eligibleRoles: Role[];
  escalationTimeoutSec: number;
  conflictedUserIds: string[];
  source: "CAPTURED" | "BACKFILLED";
}

/** The level currently in force, or null when the snapshot is missing/inconsistent (callers must fail closed). */
export function effectiveLevel<L extends { level: number }>(request: {
  escalationLevel: number;
  policyLevels: L[];
}): L | null {
  return request.policyLevels.find((l) => l.level === request.escalationLevel) ?? null;
}

/** The level after the current one, or null when the request is on its last level. */
export function nextLevel<L extends { level: number }>(request: {
  escalationLevel: number;
  policyLevels: L[];
}): L | null {
  return request.policyLevels.find((l) => l.level === request.escalationLevel + 1) ?? null;
}

/** True if the user authored a governing policy revision anywhere in the request's chain. */
export function isPolicyEditorConflict(userId: string, policyLevels: { conflictedUserIds: string[] }[]): boolean {
  return policyLevels.some((l) => l.conflictedUserIds.includes(userId));
}

/**
 * The shape clients have always received as `approvalRequest.policy`, but
 * built from the frozen snapshot of the current level. `id` is the id of the
 * policy that level was copied from.
 */
export function presentGoverningPolicy(request: {
  escalationLevel: number;
  policyLevels: (SnapshotLevel & { id?: string })[];
}) {
  const current = effectiveLevel(request);
  if (!current) return null;
  const next = nextLevel(request);
  return {
    id: current.policyId,
    actionType: current.actionType,
    quorumType: current.quorumType,
    minApprovals: current.minApprovals,
    eligibleRoles: current.eligibleRoles,
    escalationTimeoutSec: current.escalationTimeoutSec,
    fallbackPolicyId: next?.policyId ?? null,
    level: current.level,
    levelCount: request.policyLevels.length,
    source: current.source,
  };
}
