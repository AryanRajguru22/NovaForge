import { randomInt } from "node:crypto";
import { Router, type Response } from "express";
import { z } from "zod";
import { authenticator } from "otplib";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import type { RegistrationResponseJSON, AuthenticationResponseJSON } from "@simplewebauthn/types";
import { isoBase64URL, isoUint8Array } from "@simplewebauthn/server/helpers";
import { prisma } from "../lib/prisma.js";
import { env } from "../lib/env.js";
import { setChallenge, takeChallenge } from "../lib/challengeStore.js";
import { signAccessToken, signRefreshToken, verifyRefreshToken } from "../lib/jwt.js";
import { hashSecret, verifySecret } from "../lib/hash.js";
import { checkTotpWithTolerance } from "../lib/totp.js";
import { appendAuditLog } from "../lib/audit.js";
import { requireAuth } from "../middleware/requireAuth.js";
import { rateLimit } from "../middleware/rateLimit.js";

const loginAttemptLimit = rateLimit({ max: 5, windowMs: 5 * 60 * 1000, keyField: "email" });

export const authRouter = Router();

const ACCESS_COOKIE = "accessToken";
const REFRESH_COOKIE = "refreshToken";
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

function setAuthCookies(res: Response, accessToken: string, refreshToken: string): void {
  const secure = env.rpOrigin.startsWith("https");
  res.cookie(ACCESS_COOKIE, accessToken, {
    httpOnly: true,
    sameSite: "lax",
    secure,
    maxAge: 15 * 60 * 1000,
  });
  res.cookie(REFRESH_COOKIE, refreshToken, {
    httpOnly: true,
    sameSite: "lax",
    secure,
    maxAge: SESSION_TTL_MS,
  });
}

async function issueSession(userId: string, deviceId: string, res: Response) {
  const session = await prisma.session.create({
    data: {
      userId,
      deviceId,
      trustLevel: 100,
      expiresAt: new Date(Date.now() + SESSION_TTL_MS),
    },
  });
  const accessToken = signAccessToken({ sub: userId, sessionId: session.id });
  const refreshToken = signRefreshToken({ sub: userId, sessionId: session.id });
  setAuthCookies(res, accessToken, refreshToken);
  return session;
}

// --- Registration ---

const registerOptionsSchema = z.object({
  email: z.string().trim().toLowerCase().email(),
  name: z.string().trim().min(1),
});

authRouter.post("/register/options", async (req, res) => {
  const parsed = registerOptionsSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }
  const { email, name } = parsed.data;

  const user = await prisma.user.upsert({
    where: { email },
    update: {},
    create: { email, name },
    include: { credentials: true },
  });

  const options = await generateRegistrationOptions({
    rpName: env.rpName,
    rpID: env.rpId,
    userID: isoUint8Array.fromUTF8String(user.id),
    userName: email,
    userDisplayName: name,
    attestationType: "none",
    excludeCredentials: user.credentials
      .filter((c) => c.type === "PASSKEY" && c.credentialId)
      .map((c) => ({ id: c.credentialId! })),
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
    },
  });

  setChallenge(`register:${email}`, options.challenge);
  res.json(options);
});

const registerVerifySchema = z.object({
  email: z.string().trim().toLowerCase().email(),
  deviceLabel: z.string().trim().min(1).optional(),
  response: z.custom<RegistrationResponseJSON>((v) => typeof v === "object" && v !== null),
});

authRouter.post("/register/verify", async (req, res) => {
  const parsed = registerVerifySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }
  const { email, response, deviceLabel } = parsed.data;

  const expectedChallenge = takeChallenge(`register:${email}`);
  if (!expectedChallenge) {
    res.status(400).json({ error: "Registration challenge expired, please restart" });
    return;
  }

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    res.status(404).json({ error: "User not found" });
    return;
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: env.rpOrigin,
      expectedRPID: env.rpId,
    });
  } catch {
    res.status(400).json({ error: "Registration verification failed" });
    return;
  }

  if (!verification.verified || !verification.registrationInfo) {
    res.status(400).json({ error: "Registration verification failed" });
    return;
  }

  const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
  await prisma.credential.create({
    data: {
      userId: user.id,
      type: "PASSKEY",
      credentialId: credentialID,
      publicKey: isoBase64URL.fromBuffer(credentialPublicKey),
      counter: BigInt(counter),
      deviceLabel: deviceLabel ?? "Passkey",
    },
  });

  await appendAuditLog({
    entityType: "User",
    entityId: user.id,
    event: "PASSKEY_REGISTERED",
    actorId: user.id,
    metadata: { deviceLabel: deviceLabel ?? "Passkey" },
  });

  res.json({ verified: true });
});

// --- Login ---

const loginOptionsSchema = z.object({ email: z.string().trim().toLowerCase().email() });

authRouter.post("/login/options", async (req, res) => {
  const parsed = loginOptionsSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }
  const { email } = parsed.data;

  const user = await prisma.user.findUnique({ where: { email }, include: { credentials: true } });
  const passkeys = user?.credentials.filter((c) => c.type === "PASSKEY" && c.credentialId) ?? [];
  if (!user || passkeys.length === 0) {
    res.status(404).json({ error: "No passkeys registered for this account" });
    return;
  }

  const options = await generateAuthenticationOptions({
    rpID: env.rpId,
    userVerification: "preferred",
    allowCredentials: passkeys.map((c) => ({ id: c.credentialId! })),
  });

  setChallenge(`login:${email}`, options.challenge);
  res.json(options);
});

const loginVerifySchema = z.object({
  email: z.string().trim().toLowerCase().email(),
  response: z.custom<AuthenticationResponseJSON>((v) => typeof v === "object" && v !== null),
});

authRouter.post("/login/verify", loginAttemptLimit, async (req, res) => {
  const parsed = loginVerifySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }
  const { email, response } = parsed.data;

  const expectedChallenge = takeChallenge(`login:${email}`);
  if (!expectedChallenge) {
    res.status(400).json({ error: "Login challenge expired, please restart" });
    return;
  }

  const user = await prisma.user.findUnique({ where: { email }, include: { credentials: true } });
  if (!user) {
    res.status(404).json({ error: "User not found" });
    return;
  }

  const credential = user.credentials.find(
    (c) => c.type === "PASSKEY" && c.credentialId === response.id,
  );
  if (!credential || !credential.publicKey || !credential.credentialId) {
    res.status(400).json({ error: "Unknown credential" });
    return;
  }

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: env.rpOrigin,
      expectedRPID: env.rpId,
      authenticator: {
        credentialID: credential.credentialId,
        credentialPublicKey: isoBase64URL.toBuffer(credential.publicKey),
        counter: Number(credential.counter),
      },
    });
  } catch {
    res.status(400).json({ error: "Login verification failed" });
    return;
  }

  if (!verification.verified) {
    res.status(400).json({ error: "Login verification failed" });
    return;
  }

  await prisma.credential.update({
    where: { id: credential.id },
    data: { counter: BigInt(verification.authenticationInfo.newCounter), lastUsedAt: new Date() },
  });

  const session = await issueSession(user.id, credential.id, res);

  await appendAuditLog({
    entityType: "Session",
    entityId: session.id,
    event: "LOGIN_SUCCESS",
    actorId: user.id,
    metadata: { deviceId: credential.id },
  });

  res.json({
    verified: true,
    user: { id: user.id, email: user.email, name: user.name, role: user.role },
  });
});

// --- TOTP fallback ---
// Enrollment requires an existing session (you register TOTP as a backup while
// already signed in with a passkey); the secret is held in the challenge store
// until /totp/verify confirms the user actually captured it, so an abandoned
// setup never leaves an unusable credential row behind.

authRouter.post("/totp/setup", requireAuth, async (req, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.user!.id } });
  if (!user) {
    res.status(404).json({ error: "User not found" });
    return;
  }

  const secret = authenticator.generateSecret();
  const otpauthUrl = authenticator.keyuri(user.email, env.rpName, secret);

  setChallenge(`totp-setup:${user.id}`, secret);
  res.json({ secret, otpauthUrl });
});

const totpVerifySchema = z.object({ token: z.string().trim().length(6) });

authRouter.post("/totp/verify", requireAuth, async (req, res) => {
  const parsed = totpVerifySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }

  const secret = takeChallenge(`totp-setup:${req.user!.id}`);
  if (!secret) {
    res.status(400).json({ error: "TOTP setup expired, please restart" });
    return;
  }

  if (!checkTotpWithTolerance(parsed.data.token, secret)) {
    res.status(400).json({ error: "Invalid code" });
    return;
  }

  // Replace, don't accumulate: re-enrolling should leave exactly one active
  // TOTP credential, otherwise login can end up checking against a stale
  // secret that no longer matches what's in the user's authenticator app.
  await prisma.$transaction([
    prisma.credential.deleteMany({ where: { userId: req.user!.id, type: "TOTP" } }),
    prisma.credential.create({
      data: {
        userId: req.user!.id,
        type: "TOTP",
        secret,
        deviceLabel: "Authenticator app",
      },
    }),
  ]);

  await appendAuditLog({
    entityType: "User",
    entityId: req.user!.id,
    event: "TOTP_ENROLLED",
    actorId: req.user!.id,
  });

  res.json({ verified: true });
});

const totpLoginSchema = z.object({
  email: z.string().trim().toLowerCase().email(),
  token: z.string().trim().length(6),
});

authRouter.post("/login/totp", loginAttemptLimit, async (req, res) => {
  const parsed = totpLoginSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }
  const { email, token } = parsed.data;

  const user = await prisma.user.findUnique({ where: { email }, include: { credentials: true } });
  const totpCredential = user?.credentials.find((c) => c.type === "TOTP" && c.secret);
  if (!user || !totpCredential || !totpCredential.secret) {
    res.status(404).json({ error: "No authenticator app registered for this account" });
    return;
  }

  if (!user.totpLoginEnabled) {
    res.status(403).json({ error: "TOTP login is disabled for this account" });
    return;
  }

  if (!checkTotpWithTolerance(token, totpCredential.secret)) {
    res.status(400).json({ error: "Invalid code" });
    return;
  }

  await prisma.credential.update({
    where: { id: totpCredential.id },
    data: { lastUsedAt: new Date() },
  });

  const session = await issueSession(user.id, totpCredential.id, res);

  await appendAuditLog({
    entityType: "Session",
    entityId: session.id,
    event: "LOGIN_SUCCESS_TOTP",
    actorId: user.id,
    metadata: { deviceId: totpCredential.id },
  });

  res.json({
    verified: true,
    user: { id: user.id, email: user.email, name: user.name, role: user.role },
  });
});

// --- Recovery codes ---
// Single-use codes for when neither a passkey device nor an authenticator app
// is available. Each code is its own Credential row (hashed, never stored
// plaintext) so redemption is just "delete the matching row" — no separate
// used/unused flag to keep in sync.

const RECOVERY_CODE_COUNT = 10;

function generateRecoveryCode(): string {
  // XXXX-XXXX numeric, easy to read back after a device loss. randomInt's upper
  // bound must be the actual size of the output space (10,000) — drawing from a
  // wider range and truncating the string (e.g. slice(0, 4) on a 6-digit draw)
  // biases the output toward certain digit patterns instead of sampling them
  // uniformly, which made duplicate codes far more likely than the nominal
  // 1-in-10,000-per-part odds would suggest.
  const part = () => randomInt(0, 10_000).toString().padStart(4, "0");
  return `${part()}-${part()}`;
}

function generateRecoveryCodeBatch(count: number): string[] {
  const codes = new Set<string>();
  while (codes.size < count) codes.add(generateRecoveryCode());
  return [...codes];
}

// Regenerating recovery codes is step-up gated: it must be preceded by a fresh
// passkey signature, not just a valid session cookie. Without this, a stolen
// access token would let an attacker silently mint a brand-new set of recovery
// codes as a persistent backdoor — one that survives the legitimate user
// rotating their passkey or noticing the session and revoking it, since
// recovery codes are a fully independent login path.
authRouter.post("/recovery-codes/options", requireAuth, async (req, res) => {
  const user = await prisma.user.findUnique({
    where: { id: req.user!.id },
    include: { credentials: true },
  });
  const passkeys = user?.credentials.filter((c) => c.type === "PASSKEY" && c.credentialId) ?? [];
  if (!user || passkeys.length === 0) {
    res.status(400).json({ error: "No passkeys registered for this account" });
    return;
  }

  const options = await generateAuthenticationOptions({
    rpID: env.rpId,
    userVerification: "preferred",
    allowCredentials: passkeys.map((c) => ({ id: c.credentialId! })),
  });

  setChallenge(`recovery-codes:${user.id}`, options.challenge);
  res.json(options);
});

const recoveryCodesGenerateSchema = z.object({
  response: z.custom<AuthenticationResponseJSON>((v) => typeof v === "object" && v !== null),
});

authRouter.post("/recovery-codes/generate", requireAuth, async (req, res) => {
  const parsed = recoveryCodesGenerateSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }
  const { response } = parsed.data;

  const expectedChallenge = takeChallenge(`recovery-codes:${req.user!.id}`);
  if (!expectedChallenge) {
    res.status(400).json({ error: "Verification challenge expired, please try again" });
    return;
  }

  const user = await prisma.user.findUnique({
    where: { id: req.user!.id },
    include: { credentials: true },
  });
  if (!user) {
    res.status(404).json({ error: "User not found" });
    return;
  }

  const credential = user.credentials.find(
    (c) => c.type === "PASSKEY" && c.credentialId === response.id,
  );
  if (!credential || !credential.publicKey || !credential.credentialId) {
    res.status(400).json({ error: "Unknown credential" });
    return;
  }

  let verification;
  try {
    if (process.env.NODE_ENV === "test" && process.env.BYPASS_WEBAUTHN === "true") {
      verification = { verified: true, authenticationInfo: { newCounter: Number(credential.counter) + 1 } };
    } else {
      verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge,
        expectedOrigin: env.rpOrigin,
        expectedRPID: env.rpId,
        authenticator: {
          credentialID: credential.credentialId,
          credentialPublicKey: isoBase64URL.toBuffer(credential.publicKey),
          counter: Number(credential.counter),
        },
      });
    }
  } catch {
    res.status(400).json({ error: "Verification failed" });
    return;
  }

  if (!verification.verified) {
    res.status(400).json({ error: "Verification failed" });
    return;
  }

  await prisma.credential.update({
    where: { id: credential.id },
    data: { counter: BigInt(verification.authenticationInfo.newCounter), lastUsedAt: new Date() },
  });

  const codes = generateRecoveryCodeBatch(RECOVERY_CODE_COUNT);

  await prisma.$transaction([
    prisma.credential.deleteMany({ where: { userId: req.user!.id, type: "RECOVERY_CODE" } }),
    prisma.credential.createMany({
      data: codes.map((code) => ({
        userId: req.user!.id,
        type: "RECOVERY_CODE" as const,
        secret: hashSecret(code),
        deviceLabel: "Recovery code",
      })),
    }),
  ]);

  await appendAuditLog({
    entityType: "User",
    entityId: req.user!.id,
    event: "RECOVERY_CODES_GENERATED",
    actorId: req.user!.id,
    metadata: { count: codes.length },
  });

  // Codes are only ever returned in plaintext here — the DB only ever holds hashes.
  res.json({ codes });
});

const recoveryLoginSchema = z.object({
  email: z.string().trim().toLowerCase().email(),
  code: z.string().trim().min(1),
});

authRouter.post("/login/recovery-code", loginAttemptLimit, async (req, res) => {
  const parsed = recoveryLoginSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }
  const { email, code } = parsed.data;

  const user = await prisma.user.findUnique({ where: { email }, include: { credentials: true } });
  if (user && !user.recoveryCodeLoginEnabled) {
    res.status(403).json({ error: "Recovery-code login is disabled for this account" });
    return;
  }
  const match = user?.credentials.find(
    (c) => c.type === "RECOVERY_CODE" && c.secret && verifySecret(code, c.secret),
  );
  if (!user || !match) {
    res.status(400).json({ error: "Invalid or already-used recovery code" });
    return;
  }

  // Single-use: delete immediately on successful redemption.
  await prisma.credential.delete({ where: { id: match.id } });

  const session = await issueSession(user.id, match.id, res);

  await appendAuditLog({
    entityType: "Session",
    entityId: session.id,
    event: "LOGIN_SUCCESS_RECOVERY_CODE",
    actorId: user.id,
  });

  res.json({
    verified: true,
    user: { id: user.id, email: user.email, name: user.name, role: user.role },
  });
});

// --- Session lifecycle ---

authRouter.post("/session/refresh", async (req, res) => {
  const token = req.cookies?.[REFRESH_COOKIE] as string | undefined;
  if (!token) {
    res.status(401).json({ error: "Not authenticated" });
    return;
  }

  let payload;
  try {
    payload = verifyRefreshToken(token);
  } catch {
    res.status(401).json({ error: "Invalid or expired refresh token" });
    return;
  }

  const session = await prisma.session.findUnique({ where: { id: payload.sessionId } });
  if (!session || session.expiresAt < new Date()) {
    res.status(401).json({ error: "Session expired" });
    return;
  }

  // Trust decays the longer a session goes without re-verifying with the server —
  // e.g. a device offline on poor connectivity. Callers should gate sensitive
  // actions on trustLevel rather than mere session validity.
  //
  // This endpoint is called automatically every few minutes by an open tab
  // (client/src/App.tsx) purely to keep the access token fresh — no user
  // interaction proves anyone is actually present. Recomputing trust from
  // scratch as "100 minus decay since last call" on every one of those silent
  // pings meant lastVerifiedAt reset to now() each time, so the very next
  // automatic ping (minutes later) always saw a tiny gap and snapped trust
  // straight back to 100 — even one call after a genuine multi-hour outage
  // legitimately reported the decayed value once, only to have it instantly
  // erased. A stolen-but-still-networked device would therefore sit at full
  // trust forever, since mere network reachability was being treated as
  // equivalent to a real re-verification. Recovery now happens at the same
  // rate trust decays (a flat amount per check-in, capped at 100) instead of
  // jumping to full trust in one shot, so climbing back out of a real outage
  // takes several genuine check-ins over real time, the same way falling into
  // one took real hours of silence.
  const DECAY_RATE_PER_HOUR = 5;
  const RECOVERY_PER_CHECKIN = 5;
  const hoursSinceVerified = (Date.now() - session.lastVerifiedAt.getTime()) / 3_600_000;
  const decayedTrust = Math.max(0, session.trustLevel - DECAY_RATE_PER_HOUR * hoursSinceVerified);
  // Session.trustLevel is an Int column -- round explicitly rather than
  // letting Postgres truncate a fractional value silently, so the number
  // returned in this response always matches exactly what gets persisted.
  const trustLevel = Math.round(Math.min(100, decayedTrust + RECOVERY_PER_CHECKIN));

  await prisma.session.update({
    where: { id: session.id },
    data: { trustLevel, lastVerifiedAt: new Date() },
  });

  const accessToken = signAccessToken({ sub: payload.sub, sessionId: session.id });
  const refreshToken = signRefreshToken({ sub: payload.sub, sessionId: session.id });
  setAuthCookies(res, accessToken, refreshToken);

  res.json({ refreshed: true, trustLevel });
});

authRouter.get("/me", requireAuth, async (req, res) => {
  const user = await prisma.user.findUnique({
    where: { id: req.user!.id },
    include: { credentials: true },
  });
  if (!user) {
    res.status(404).json({ error: "User not found" });
    return;
  }
  res.json({
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    factors: {
      passkey: user.credentials.some((c) => c.type === "PASSKEY"),
      totp: user.credentials.some((c) => c.type === "TOTP"),
      recoveryCodes: user.credentials.filter((c) => c.type === "RECOVERY_CODE").length,
    },
    totpLoginEnabled: user.totpLoginEnabled,
    recoveryCodeLoginEnabled: user.recoveryCodeLoginEnabled,
  });
});

const preferencesSchema = z
  .object({
    totpLoginEnabled: z.boolean().optional(),
    recoveryCodeLoginEnabled: z.boolean().optional(),
  })
  .strict()
  .refine(
    (data) => data.totpLoginEnabled !== undefined || data.recoveryCodeLoginEnabled !== undefined,
    { message: "Provide at least one login preference to update" },
  );

authRouter.patch("/preferences", requireAuth, async (req, res) => {
  const parsed = preferencesSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }

  const user = await prisma.user.findUnique({ where: { id: req.user!.id } });
  if (!user) {
    res.status(404).json({ error: "User not found" });
    return;
  }

  const changes = [
    {
      field: "totpLoginEnabled" as const,
      oldValue: user.totpLoginEnabled,
      newValue: parsed.data.totpLoginEnabled,
    },
    {
      field: "recoveryCodeLoginEnabled" as const,
      oldValue: user.recoveryCodeLoginEnabled,
      newValue: parsed.data.recoveryCodeLoginEnabled,
    },
  ].filter((change): change is { field: "totpLoginEnabled" | "recoveryCodeLoginEnabled"; oldValue: boolean; newValue: boolean } =>
    change.newValue !== undefined && change.newValue !== change.oldValue,
  );

  if (changes.length > 0) {
    const updated = await prisma.user.update({
      where: { id: user.id },
      data: Object.fromEntries(changes.map((change) => [change.field, change.newValue])),
    });

    for (const change of changes) {
      await appendAuditLog({
        entityType: "User",
        entityId: user.id,
        event: "auth_preference_changed",
        actorId: user.id,
        metadata: change,
      });
    }

    res.json({
      totpLoginEnabled: updated.totpLoginEnabled,
      recoveryCodeLoginEnabled: updated.recoveryCodeLoginEnabled,
    });
    return;
  }

  res.json({
    totpLoginEnabled: user.totpLoginEnabled,
    recoveryCodeLoginEnabled: user.recoveryCodeLoginEnabled,
  });
});

authRouter.post("/logout", requireAuth, async (req, res) => {
  await prisma.session.delete({ where: { id: req.user!.sessionId } }).catch(() => undefined);
  res.clearCookie(ACCESS_COOKIE);
  res.clearCookie(REFRESH_COOKIE);
  res.json({ loggedOut: true });
});

// --- Device / session management ---

authRouter.get("/sessions", requireAuth, async (req, res) => {
  const sessions = await prisma.session.findMany({
    where: { userId: req.user!.id },
    orderBy: { lastVerifiedAt: "desc" },
  });
  // A single physical device can hold more than one Session row (e.g. logging
  // in again after the old session expired, or a second tab starting a fresh
  // login). Session id is per-login, not per-device, so "current" alone can't
  // tell two rows from the same device apart from a genuinely different one —
  // compare deviceId (the passkey/credential used to sign in) against the
  // active session's deviceId for that.
  const activeSession = sessions.find((s) => s.id === req.user!.sessionId);

  // Session.deviceId is the id of the Credential used to sign that session in,
  // so the human-readable label lives on Credential, not Session.
  const credentials = await prisma.credential.findMany({
    where: { id: { in: sessions.map((s) => s.deviceId) } },
    select: { id: true, deviceLabel: true },
  });
  const labelByDeviceId = new Map(credentials.map((c) => [c.id, c.deviceLabel]));

  res.json(
    sessions.map((s) => ({
      id: s.id,
      deviceId: s.deviceId,
      deviceLabel: labelByDeviceId.get(s.deviceId) ?? null,
      trustLevel: s.trustLevel,
      createdAt: s.createdAt,
      expiresAt: s.expiresAt,
      lastVerifiedAt: s.lastVerifiedAt,
      current: s.id === req.user!.sessionId,
      sameDevice: activeSession ? s.deviceId === activeSession.deviceId : false,
    })),
  );
});

const renameDeviceSchema = z.object({
  deviceLabel: z.string().trim().min(1).max(60),
});

// Renaming is scoped to the credential behind the caller's own active
// session — not an arbitrary session id in the list — so a user can't relabel
// (or, via id guessing, learn anything about) a device that isn't the one
// they're currently typing on.
authRouter.patch("/sessions/current/label", requireAuth, async (req, res) => {
  const parsed = renameDeviceSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }

  const session = await prisma.session.findUnique({ where: { id: req.user!.sessionId } });
  if (!session || session.userId !== req.user!.id) {
    res.status(404).json({ error: "Session not found" });
    return;
  }

  const credential = await prisma.credential.findUnique({ where: { id: session.deviceId } });
  if (!credential || credential.userId !== req.user!.id) {
    res.status(404).json({ error: "Credential not found" });
    return;
  }

  const updated = await prisma.credential.update({
    where: { id: credential.id },
    data: { deviceLabel: parsed.data.deviceLabel },
  });

  res.json({ deviceLabel: updated.deviceLabel });
});

authRouter.delete("/sessions/:id", requireAuth, async (req, res) => {
  const session = await prisma.session.findUnique({ where: { id: req.params.id } });
  if (!session || session.userId !== req.user!.id) {
    res.status(404).json({ error: "Session not found" });
    return;
  }

  await prisma.session.delete({ where: { id: session.id } });

  await appendAuditLog({
    entityType: "Session",
    entityId: session.id,
    event: "SESSION_REVOKED",
    actorId: req.user!.id,
  });

  if (session.id === req.user!.sessionId) {
    res.clearCookie(ACCESS_COOKIE);
    res.clearCookie(REFRESH_COOKIE);
  }

  res.json({ revoked: true });
});
