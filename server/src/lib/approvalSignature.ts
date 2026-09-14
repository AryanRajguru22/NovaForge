import { createHash, randomBytes } from "node:crypto";
import { z } from "zod";
import { isoBase64URL, parseAuthenticatorData, verifySignature } from "@simplewebauthn/server/helpers";
import { canonicalJson, sha256Hex } from "./canonicalJson.js";

// Cryptographically bound approval decisions.
//
// A WebAuthn assertion signs authenticatorData || SHA-256(clientDataJSON),
// and the only relying-party-controlled value inside clientDataJSON is the
// challenge. So the challenge IS the binding: the server builds a decision
// statement naming exactly what is being decided, serializes it with RFC 8785
// canonical JSON, and uses SHA-256(statement) as the WebAuthn challenge.
// A valid signature therefore proves the approver's authenticator signed
// that exact statement -- request, action, subject digest, approver, decision,
// reason and a single-use nonce -- and nothing else. Changing any field
// changes the challenge, which invalidates the signature.
//
// The full evidence (statement, clientDataJSON, authenticatorData, signature,
// credential public key) is stored on the ApprovalVote row so it can be
// re-verified later without trusting NovaForge's own "verified" flag.

export const DECISION_STATEMENT_VERSION = "novaforge.approval-decision/v1";
export const DECISION_STATEMENT_TTL_MS = 5 * 60 * 1000;
export const DECISIONS = ["APPROVE", "REJECT", "POSTPONE"] as const;
export type Decision = (typeof DECISIONS)[number];

export interface DecisionStatement {
  v: typeof DECISION_STATEMENT_VERSION;
  requestId: string;
  actionId: string;
  actionType: string;
  subjectDigest: string;
  approverId: string;
  decision: Decision;
  reason: string | null;
  rpId: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
}

const statementSchema = z
  .object({
    v: z.literal(DECISION_STATEMENT_VERSION),
    requestId: z.string().min(1),
    actionId: z.string().min(1),
    actionType: z.string().min(1),
    subjectDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
    approverId: z.string().min(1),
    decision: z.enum(DECISIONS),
    reason: z.string().nullable(),
    rpId: z.string().min(1),
    nonce: z.string().min(16),
    issuedAt: z.string().datetime(),
    expiresAt: z.string().datetime(),
  })
  .strict();

/** Digest of what is being approved. Covers the action type and its exact payload. */
export function computeSubjectDigest(type: string, payload: unknown): string {
  return `sha256:${sha256Hex(canonicalJson({ type, payload }))}`;
}

export function buildDecisionStatement(input: {
  requestId: string;
  actionId: string;
  actionType: string;
  subjectDigest: string;
  approverId: string;
  decision: Decision;
  reason: string | null;
  rpId: string;
  now?: Date;
}): DecisionStatement {
  const issuedAt = input.now ?? new Date();
  return {
    v: DECISION_STATEMENT_VERSION,
    requestId: input.requestId,
    actionId: input.actionId,
    actionType: input.actionType,
    subjectDigest: input.subjectDigest,
    approverId: input.approverId,
    decision: input.decision,
    reason: input.reason,
    rpId: input.rpId,
    nonce: isoBase64URL.fromBuffer(randomBytes(32)),
    issuedAt: issuedAt.toISOString(),
    expiresAt: new Date(issuedAt.getTime() + DECISION_STATEMENT_TTL_MS).toISOString(),
  };
}

export function serializeStatement(statement: DecisionStatement): string {
  return canonicalJson(statement);
}

/** Raw 32-byte challenge for generateAuthenticationOptions. */
export function statementChallengeBytes(serialized: string): Uint8Array {
  return new Uint8Array(createHash("sha256").update(serialized, "utf8").digest());
}

/** base64url challenge, as it appears in clientDataJSON and expectedChallenge. */
export function statementChallenge(serialized: string): string {
  return isoBase64URL.fromBuffer(statementChallengeBytes(serialized));
}

/** Parses a stored statement, rejecting anything not in exact canonical form. */
export function parseStatement(serialized: string): DecisionStatement | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    return null;
  }
  const result = statementSchema.safeParse(parsed);
  if (!result.success) return null;
  if (canonicalJson(result.data) !== serialized) return null;
  return result.data as DecisionStatement;
}

export interface StoredVoteEvidence {
  requestId: string;
  approverId: string;
  decision: string;
  reason: string | null;
  signature: string;
  signedStatement: string | null;
  statementHash: string | null;
  clientDataJSON: string | null;
  authenticatorData: string | null;
  credentialPublicKey: string | null;
}

export interface StoredSubject {
  id: string;
  type: string;
  payload: unknown;
  payloadDigest: string | null;
}

/**
 * Independently re-verifies a recorded vote: the statement is canonical and
 * matches every recorded field and the action's current subject, the
 * clientDataJSON challenge is SHA-256(statement), the authenticator data is
 * for this RP with user presence and verification, and the signature is valid
 * under the stored credential public key.
 */
export async function verifyStoredVoteEvidence(
  vote: StoredVoteEvidence,
  action: StoredSubject,
  expected: { rpId: string; origin: string },
): Promise<{ valid: boolean; errors: string[] }> {
  const errors: string[] = [];
  const { signedStatement, statementHash, clientDataJSON, authenticatorData, credentialPublicKey } = vote;
  if (!signedStatement || !statementHash || !clientDataJSON || !authenticatorData || !credentialPublicKey) {
    return { valid: false, errors: ["Vote has no decision-binding evidence"] };
  }

  const statement = parseStatement(signedStatement);
  if (!statement) {
    errors.push("Signed statement is malformed or not canonical");
  } else {
    if (sha256Hex(signedStatement) !== statementHash) errors.push("Statement hash mismatch");
    if (statement.requestId !== vote.requestId) errors.push("Statement requestId does not match the vote");
    if (statement.approverId !== vote.approverId) errors.push("Statement approverId does not match the vote");
    if (statement.decision !== vote.decision) errors.push("Statement decision does not match the vote");
    if (statement.reason !== (vote.reason ?? null)) errors.push("Statement reason does not match the vote");
    if (statement.actionId !== action.id) errors.push("Statement actionId does not match the action");
    if (statement.actionType !== action.type) errors.push("Statement actionType does not match the action");
    if (statement.rpId !== expected.rpId) errors.push("Statement rpId mismatch");
    const currentDigest = computeSubjectDigest(action.type, action.payload);
    if (statement.subjectDigest !== action.payloadDigest || statement.subjectDigest !== currentDigest) {
      errors.push("Statement subject digest does not match the action's payload");
    }
  }

  let clientDataBytes: Uint8Array;
  let authDataBytes: Uint8Array;
  let signatureBytes: Uint8Array;
  let publicKeyBytes: Uint8Array;
  try {
    clientDataBytes = isoBase64URL.toBuffer(clientDataJSON);
    authDataBytes = isoBase64URL.toBuffer(authenticatorData);
    signatureBytes = isoBase64URL.toBuffer(vote.signature);
    publicKeyBytes = isoBase64URL.toBuffer(credentialPublicKey);
  } catch {
    return { valid: false, errors: [...errors, "Evidence is not valid base64url"] };
  }

  try {
    const clientData = JSON.parse(Buffer.from(clientDataBytes).toString("utf8")) as {
      type?: string;
      challenge?: string;
      origin?: string;
    };
    if (clientData.type !== "webauthn.get") errors.push("clientDataJSON type is not webauthn.get");
    if (clientData.challenge !== statementChallenge(signedStatement)) {
      errors.push("clientDataJSON challenge is not SHA-256 of the signed statement");
    }
    if (clientData.origin !== expected.origin) errors.push("clientDataJSON origin mismatch");
  } catch {
    errors.push("clientDataJSON is not valid JSON");
  }

  try {
    const parsedAuthData = parseAuthenticatorData(authDataBytes);
    const expectedRpIdHash = createHash("sha256").update(expected.rpId).digest();
    if (!Buffer.from(parsedAuthData.rpIdHash).equals(expectedRpIdHash)) errors.push("authenticatorData rpIdHash mismatch");
    if (!parsedAuthData.flags.up) errors.push("authenticatorData lacks user presence");
    if (!parsedAuthData.flags.uv) errors.push("authenticatorData lacks user verification");
  } catch {
    errors.push("authenticatorData is malformed");
  }

  try {
    const signedData = Buffer.concat([
      Buffer.from(authDataBytes),
      createHash("sha256").update(clientDataBytes).digest(),
    ]);
    const ok = await verifySignature({
      signature: signatureBytes,
      data: new Uint8Array(signedData),
      credentialPublicKey: publicKeyBytes,
    });
    if (!ok) errors.push("Signature does not verify under the credential public key");
  } catch {
    errors.push("Signature verification failed");
  }

  return { valid: errors.length === 0, errors };
}
