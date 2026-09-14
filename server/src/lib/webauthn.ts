import { verifyAuthenticationResponse } from "@simplewebauthn/server";
import type { AuthenticationResponseJSON } from "@simplewebauthn/types";
import { isoBase64URL } from "@simplewebauthn/server/helpers";
import type { Credential } from "@prisma/client";
import { env } from "./env.js";

// One implementation of "verify a passkey assertion against one of this
// user's registered credentials", shared by login, step-up gates and
// approval votes. There is deliberately no test/bypass mode: the test suite
// uses a real software authenticator (server/test/softAuthenticator.ts).

export type PasskeyVerification =
  | { ok: true; credential: Credential; newCounter: number }
  | { ok: false; error: "UNKNOWN_CREDENTIAL" | "VERIFICATION_FAILED" };

export async function verifyPasskeyAssertion(opts: {
  credentials: Credential[];
  response: AuthenticationResponseJSON;
  expectedChallenge: string;
  requireUserVerification?: boolean;
}): Promise<PasskeyVerification> {
  const credential = opts.credentials.find(
    (c) => c.type === "PASSKEY" && c.credentialId !== null && c.credentialId === opts.response?.id,
  );
  if (!credential || !credential.publicKey || !credential.credentialId) {
    return { ok: false, error: "UNKNOWN_CREDENTIAL" };
  }
  try {
    const verification = await verifyAuthenticationResponse({
      response: opts.response,
      expectedChallenge: opts.expectedChallenge,
      expectedOrigin: env.rpOrigin,
      expectedRPID: env.rpId,
      requireUserVerification: opts.requireUserVerification ?? true,
      authenticator: {
        credentialID: credential.credentialId,
        credentialPublicKey: isoBase64URL.toBuffer(credential.publicKey),
        counter: Number(credential.counter),
      },
    });
    if (!verification.verified) return { ok: false, error: "VERIFICATION_FAILED" };
    return { ok: true, credential, newCounter: verification.authenticationInfo.newCounter };
  } catch {
    return { ok: false, error: "VERIFICATION_FAILED" };
  }
}

export function normalizeEmail(email: unknown): string {
  return String(email ?? "").trim().toLowerCase();
}
