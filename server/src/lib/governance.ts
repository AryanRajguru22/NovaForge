import type { Request, RequestHandler, Response } from "express";
import type { Prisma } from "@prisma/client";
import type { AuthenticationResponseJSON } from "@simplewebauthn/types";
import { appendAuditLog, auditedTransaction } from "./audit.js";
import { beginStepUp, verifyStepUp, type StepUpPurpose, type StepUpResult } from "./stepUp.js";
import { POLICY_GRAPH_LOCK_KEY } from "./policySnapshot.js";
import { requireTrust } from "../middleware/requireTrust.js";

// Shared guards for governance mutations (policies, roles, vote weights,
// account status). Every one of them must, on the server:
//   1. be performed by an authorised role           (route-level guard)
//   2. come from a session whose effective trust is high enough  (governanceTrust)
//   3. carry a fresh passkey assertion, single-use and bound to a purpose
//                                                   (enforceGovernanceStepUp)
// and record refusals of 2 and 3 in the audit log. Successful operations are
// audited by the route in the same transaction as the change.

/** pg_advisory_xact_lock key serialising changes to the SUPER_ADMIN set. */
export const SUPER_ADMIN_SET_LOCK_KEY = 727002;

// "enrollment-token" (older purpose) also gates issuing enrollment links and invitations: both grant a
// credential, and an invitation can create a SUPER_ADMIN, so they get the same trust check and audited refusals.
export type GovernancePurpose = Extract<StepUpPurpose, "policy-governance" | "user-governance" | "enrollment-token">;

async function recordGovernanceRefusal(
  actorId: string,
  event: "GOVERNANCE_STEP_UP_FAILED" | "GOVERNANCE_TRUST_DENIED",
  metadata: Record<string, unknown>,
): Promise<void> {
  await auditedTransaction((tx) =>
    appendAuditLog(tx, { entityType: "Governance", entityId: actorId, event, actorId, metadata }),
  );
}

/** Route middleware: effective (decayed) session trust, with refusals audited. */
export function governanceTrust(operation: string): RequestHandler {
  return requireTrust(undefined, {
    onDeny: (req, denial) =>
      recordGovernanceRefusal(req.user!.id, "GOVERNANCE_TRUST_DENIED", { operation, ...denial }),
  });
}

/** Handler that starts a step-up ceremony for `purpose` (call after requireAuth + the role guard). */
export function governanceStepUpOptions(purpose: GovernancePurpose): RequestHandler {
  return async (req, res) => {
    const options = await beginStepUp(req.user!.id, purpose);
    if (!options) {
      res.status(400).json({ error: "No passkeys registered for this account" });
      return;
    }
    res.json(options);
  };
}

export type VerifiedStepUp = Extract<StepUpResult, { ok: true }>;

/**
 * Verifies the `response` member of the request body as a fresh passkey
 * assertion for `purpose`. On any failure it audits GOVERNANCE_STEP_UP_FAILED,
 * sends the refusal and returns null; on success the caller must pass the
 * result to recordStepUpCounter() inside its own transaction.
 *
 *   403 STEP_UP_REQUIRED  no assertion supplied (nothing is consumed)
 *   400 STEP_UP_FAILED    challenge missing/expired/already used, or the
 *                         assertion does not verify (UV is always required)
 */
export async function enforceGovernanceStepUp(
  req: Request,
  res: Response,
  purpose: GovernancePurpose,
  operation: string,
): Promise<VerifiedStepUp | null> {
  const response = (req.body as { response?: unknown } | undefined)?.response;
  const actorId = req.user!.id;

  if (!response || typeof response !== "object") {
    await recordGovernanceRefusal(actorId, "GOVERNANCE_STEP_UP_FAILED", { operation, purpose, reason: "missing" });
    res.status(403).json({ error: "Fresh passkey confirmation required", code: "STEP_UP_REQUIRED" });
    return null;
  }

  const result = await verifyStepUp(actorId, purpose, response as AuthenticationResponseJSON);
  if (!result.ok) {
    await recordGovernanceRefusal(actorId, "GOVERNANCE_STEP_UP_FAILED", { operation, purpose, reason: result.error });
    res.status(result.status).json({ error: result.error, code: "STEP_UP_FAILED" });
    return null;
  }
  return result;
}

/** Serialises writers of the policy fallback graph (also taken by the DB guard trigger). */
export async function lockPolicyGraph(tx: Prisma.TransactionClient): Promise<void> {
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(${POLICY_GRAPH_LOCK_KEY}::bigint)`;
}

/** Serialises changes that could remove the last active SUPER_ADMIN. */
export async function lockSuperAdminSet(tx: Prisma.TransactionClient): Promise<void> {
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(${SUPER_ADMIN_SET_LOCK_KEY}::bigint)`;
}
