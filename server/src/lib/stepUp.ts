import { generateAuthenticationOptions } from "@simplewebauthn/server";
import type { AuthenticationResponseJSON, PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/types";
import type { Prisma } from "@prisma/client";
import { prisma } from "./prisma.js";
import { env } from "./env.js";
import { setChallenge, takeChallenge } from "./challengeStore.js";
import { verifyPasskeyAssertion } from "./webauthn.js";

// Step-up re-authentication: a fresh passkey signature (with user
// verification) bound to one named purpose, required immediately before a
// high-impact write -- so a stolen session cookie alone isn't enough.

// "policy-governance" and "user-governance" gate the Phase 1 governance
// mutations (server/src/lib/governance.ts); the others predate them.
export type StepUpPurpose =
  | "enrollment-token"
  | "totp-enroll"
  | "recovery-codes"
  | "policy-governance"
  | "user-governance";

function challengeKey(purpose: StepUpPurpose, userId: string): string {
  return `step-up:${purpose}:${userId}`;
}

export async function beginStepUp(
  userId: string,
  purpose: StepUpPurpose,
): Promise<PublicKeyCredentialRequestOptionsJSON | null> {
  const credentials = await prisma.credential.findMany({ where: { userId, type: "PASSKEY", credentialId: { not: null } } });
  if (credentials.length === 0) return null;
  const options = await generateAuthenticationOptions({
    rpID: env.rpId,
    userVerification: "required",
    allowCredentials: credentials.map((c) => ({ id: c.credentialId! })),
  });
  setChallenge(challengeKey(purpose, userId), options.challenge);
  return options;
}

export type StepUpResult =
  | { ok: true; credentialId: string; newCounter: number }
  | { ok: false; status: number; error: string };

/** Consumes the single-use challenge and verifies the assertion. Does not write. */
export async function verifyStepUp(
  userId: string,
  purpose: StepUpPurpose,
  response: AuthenticationResponseJSON | undefined,
): Promise<StepUpResult> {
  const expectedChallenge = takeChallenge(challengeKey(purpose, userId));
  if (!expectedChallenge) return { ok: false, status: 400, error: "Passkey confirmation expired, please try again" };
  if (!response || typeof response !== "object") return { ok: false, status: 400, error: "Passkey confirmation required" };
  const credentials = await prisma.credential.findMany({ where: { userId, type: "PASSKEY" } });
  const result = await verifyPasskeyAssertion({ credentials, response, expectedChallenge, requireUserVerification: true });
  if (!result.ok) {
    return {
      ok: false,
      status: 400,
      error: result.error === "UNKNOWN_CREDENTIAL" ? "Unknown credential" : "Passkey verification failed",
    };
  }
  return { ok: true, credentialId: result.credential.id, newCounter: result.newCounter };
}

export async function recordStepUpCounter(
  tx: Prisma.TransactionClient,
  step: { credentialId: string; newCounter: number },
): Promise<void> {
  await tx.credential.update({
    where: { id: step.credentialId },
    data: { counter: BigInt(step.newCounter), lastUsedAt: new Date() },
  });
}
