import { startAuthentication } from "@simplewebauthn/browser";
import type { PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/types";
import { apiPost } from "./api.js";

// Governance mutations (policies, roles, vote weights, deletion) are refused
// by the server unless the request body carries a fresh passkey assertion.
// This asks the server for a single-use challenge, has the authenticator sign
// it, and returns the assertion to send as `response` with the mutation. The
// server enforces all of this independently; nothing here is a security
// boundary, it only lets the legitimate flow complete.
export const POLICY_STEP_UP_PATH = "/policies/step-up/options";
export const USER_GOVERNANCE_STEP_UP_PATH = "/users/governance/step-up/options";

export async function governanceProof(optionsPath: string) {
  const options = await apiPost<PublicKeyCredentialRequestOptionsJSON>(optionsPath, {});
  return startAuthentication(options);
}
