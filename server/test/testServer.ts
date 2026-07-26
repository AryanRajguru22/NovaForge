import type { AddressInfo } from "node:net";
import { httpServer, io, initEscalationService } from "../src/app.js";
import { prisma } from "../src/lib/prisma.js";
import { signAccessToken } from "../src/lib/jwt.js";
import { stopEscalationService } from "../src/lib/escalation.js";

let baseUrl = "";

// cleanupUsers() intentionally never deletes User rows (see below), so test
// emails must be unique per run — otherwise a second `npm test` run would hit
// a unique-constraint violation trying to recreate the same fixed email.
export const runSuffix = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

export async function startTestServer(): Promise<string> {
  initEscalationService(io);
  await new Promise<void>((resolve) => {
    httpServer.listen(0, resolve);
  });
  const { port } = httpServer.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${port}`;
  return baseUrl;
}

export async function stopTestServer(): Promise<void> {
  stopEscalationService();
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

/** Registers a mock passkey credential so a user can vote (BYPASS_WEBAUTHN=true skips real signature checks). */
export async function addMockPasskey(userId: string) {
  return prisma.credential.create({
    data: {
      userId,
      type: "PASSKEY",
      credentialId: `mock-cred-${userId}`,
      publicKey: "mock-public-key",
      counter: 0,
      deviceLabel: "Test Authenticator",
    },
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
}

export async function cleanupPolicies(actionTypes: string[]) {
  await prisma.approvalPolicy.deleteMany({ where: { actionType: { in: actionTypes } } });
}
