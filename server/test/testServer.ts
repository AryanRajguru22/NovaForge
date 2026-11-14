import type { AddressInfo } from "node:net";
import { httpServer, io, initEscalationService, initSocketSecurity, stopSocketSecurity } from "../src/app.js";
import { prisma } from "../src/lib/prisma.js";
import { signAccessToken } from "../src/lib/jwt.js";
import { stopEscalationService } from "../src/lib/escalation.js";
import { resetRateLimitBuckets } from "../src/middleware/rateLimit.js";
import { captureGoverningPolicy } from "../src/lib/policySnapshot.js";
import { SoftAuthenticator } from "./softAuthenticator.js";

let baseUrl = "";

// cleanupUsers() intentionally never deletes User rows (see below), so test
// emails must be unique per run — otherwise a second `npm test` run would hit
// a unique-constraint violation trying to recreate the same fixed email.
export const runSuffix = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

// sweepIntervalMs defaults to socketSecurity's own production default
// (60s) when omitted -- every existing test file's run completes in well
// under that, so the revocation sweep effectively never fires for them and
// adds no extra database load. Only a test file specifically exercising the
// sweep (server/test/socket-security.test.ts) needs to pass a short value.
export async function startTestServer(options: { sweepIntervalMs?: number } = {}): Promise<string> {
  // Each test file starts with a clean in-memory rate-limit state; every
  // request in the suite comes from 127.0.0.1.
  resetRateLimitBuckets();
  initEscalationService(io);
  initSocketSecurity(io, { sweepIntervalMs: options.sweepIntervalMs });
  await new Promise<void>((resolve) => {
    httpServer.listen(0, resolve);
  });
  const { port } = httpServer.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${port}`;
  return baseUrl;
}

export async function stopTestServer(): Promise<void> {
  stopEscalationService();
  stopSocketSecurity();
  await new Promise<void>((resolve, reject) => {
    httpServer.close((err) => (err ? reject(err) : resolve()));
  });
}

interface RequestResult<T = any> {
  status: number;
  data: T;
}

export async function apiRequest<T = any>(
  path: string,
  options: { method?: string; token?: string; refreshToken?: string; body?: object } = {},
): Promise<RequestResult<T>> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const cookies: string[] = [];
  if (options.token) cookies.push(`accessToken=${options.token}`);
  if (options.refreshToken) cookies.push(`refreshToken=${options.refreshToken}`);
  if (cookies.length > 0) headers.Cookie = cookies.join("; ");

  const res = await fetch(`${baseUrl}${path}`, {
    method: options.method ?? "GET",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  let data: T;
  try {
    data = (await res.json()) as T;
  } catch {
    data = undefined as unknown as T;
  }
  return { status: res.status, data };
}

/** Creates a user + session and returns a ready-to-use access token cookie value. */
export async function createUserWithToken(overrides: {
  email: string;
  name?: string;
  role?: "SUPER_ADMIN" | "ADMIN" | "SENIOR_APPROVER" | "APPROVER" | "MEMBER";
}) {
  const user = await prisma.user.create({
    data: {
      email: overrides.email,
      name: overrides.name ?? "Test User",
      role: overrides.role ?? "MEMBER",
    },
  });
  const session = await prisma.session.create({
    data: {
      userId: user.id,
      deviceId: "test-device",
      expiresAt: new Date(Date.now() + 3600_000),
    },
  });
  const token = signAccessToken({ sub: user.id, sessionId: session.id });
  return { user, token };
}

const authenticators = new Map<string, SoftAuthenticator>();

/**
 * Registers a real passkey for a user, backed by an in-memory software
 * authenticator. There is no signature-verification bypass anywhere: every
 * assertion a test submits is verified by the unmodified WebAuthn library.
 */
export async function addMockPasskey(userId: string, opts: { userVerified?: boolean } = {}) {
  const authenticator = new SoftAuthenticator({ credentialId: `mock-cred-${userId}`, userVerified: opts.userVerified });
  authenticators.set(userId, authenticator);
  const credential = await prisma.credential.create({
    data: {
      userId,
      type: "PASSKEY",
      credentialId: authenticator.credentialId,
      publicKey: authenticator.publicKeyBase64url,
      counter: 0,
      deviceLabel: "Test Authenticator",
    },
  });
  return Object.assign(credential, { authenticator });
}

export function authenticatorFor(userId: string): SoftAuthenticator {
  const authenticator = authenticators.get(userId);
  if (!authenticator) throw new Error(`No software authenticator registered for user ${userId}`);
  return authenticator;
}

/**
 * Mirrors the real client vote flow: request options for a specific decision
 * (the server derives the WebAuthn challenge from the decision statement),
 * sign that challenge with the voter's authenticator, then submit.
 */
export async function castVote(
  requestId: string,
  voter: { id: string; token: string },
  decision: "APPROVE" | "REJECT" | "POSTPONE",
  reason?: string,
) {
  const options = await apiRequest(`/approvals/${requestId}/options`, {
    method: "POST",
    token: voter.token,
    body: { decision, reason },
  });
  if (options.status !== 200) return options;
  const response = authenticatorFor(voter.id).createAssertion(options.data.challenge);
  return apiRequest(`/approvals/${requestId}/vote`, {
    method: "POST",
    token: voter.token,
    body: { decision, reason, response },
  });
}

// Deliberately does NOT delete the User rows themselves. AuditLog.actorId has
// no explicit onDelete behavior, so Prisma defaults to SetNull on that FK —
// deleting a user out from under audit rows that reference them would
// silently null their actorId without recomputing the row's hash, breaking
// the tamper-evident chain for reasons that have nothing to do with
// tampering. Deleting the audit rows instead just moves the problem: removing
// a row from the middle of the chain orphans every later row's prevHash
// pointer, which breaks the chain even more directly. The app itself never
// deletes users, so the simplest correct move here is to not delete them in
// tests either — callers use unique per-run emails so this never blocks
// re-running the suite.
export async function cleanupUsers(emails: string[]) {
  await prisma.approvalVote.deleteMany({ where: { approver: { email: { in: emails } } } });
  await prisma.approvalRequest.deleteMany({
    where: { action: { requestedBy: { email: { in: emails } } } },
  });
  await prisma.sensitiveAction.deleteMany({ where: { requestedBy: { email: { in: emails } } } });
  await prisma.credential.deleteMany({ where: { user: { email: { in: emails } } } });
  await prisma.session.deleteMany({ where: { user: { email: { in: emails } } } });
  await prisma.enrollmentToken.deleteMany({ where: { user: { email: { in: emails } } } });
}

export async function cleanupPolicies(actionTypes: string[]) {
  await prisma.approvalPolicy.deleteMany({ where: { actionType: { in: actionTypes } } });
}

/**
 * A fresh passkey assertion for a governance mutation (policy or user
 * governance), obtained exactly as the real client does it: ask the server for
 * a single-use challenge, sign it with the actor's software authenticator.
 * The actor needs a passkey (addMockPasskey).
 */
export async function governanceProof(actor: { id: string; token: string }, kind: "policy" | "user") {
  const path = kind === "policy" ? "/policies/step-up/options" : "/users/governance/step-up/options";
  const options = await apiRequest(path, { method: "POST", token: actor.token, body: {} });
  if (options.status !== 200) throw new Error(`step-up options failed: ${options.status} ${JSON.stringify(options.data)}`);
  return authenticatorFor(actor.id).createAssertion(options.data.challenge);
}

/**
 * Creates an ApprovalRequest the way POST /actions does -- with the immutable
 * policy snapshot captured from `policyId` and its fallback chain -- for tests
 * that need to control timing or the action directly.
 */
export async function createApprovalRequestWithSnapshot(data: { actionId: string; policyId: string; expiresAt: Date }) {
  return prisma.$transaction(async (tx) => {
    const { levels } = await captureGoverningPolicy(tx, data.policyId);
    const request = await tx.approvalRequest.create({
      data: { actionId: data.actionId, policyId: levels[0].policyId, escalationLevel: 0, expiresAt: data.expiresAt },
    });
    await tx.approvalRequestPolicyLevel.createMany({ data: levels.map((l) => ({ ...l, requestId: request.id })) });
    return request;
  });
}
