import { createHmac, randomInt, randomUUID } from "node:crypto";
import { Router, type Request, type Response } from "express";
import { z } from "zod";
import { authenticator } from "otplib";
import { Prisma } from "@prisma/client";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
} from "@simplewebauthn/server";
import type { RegistrationResponseJSON, AuthenticationResponseJSON } from "@simplewebauthn/types";
import { isoBase64URL, isoUint8Array } from "@simplewebauthn/server/helpers";
import { prisma } from "../lib/prisma.js";
import { env } from "../lib/env.js";
import { setChallenge, takeChallenge } from "../lib/challengeStore.js";
import { signAccessToken, signRefreshToken, verifyRefreshToken, generateRefreshTokenId } from "../lib/jwt.js";
import { rotateRefreshToken } from "../lib/refreshRotation.js";
import { decayedTrustLevel } from "../lib/trust.js";
import { hashSecret, verifySecret } from "../lib/hash.js";
import { matchTotpStep } from "../lib/totp.js";
import { encryptTotpSecret, decryptTotpSecret } from "../lib/totpSecretCrypto.js";
import { appendAuditLog, auditedTransaction } from "../lib/audit.js";
import { normalizeEmail, verifyPasskeyAssertion } from "../lib/webauthn.js";
import { beginStepUp, recordStepUpCounter, verifyStepUp } from "../lib/stepUp.js";
import { fallbackSubject, reserveAuthAttempt, resetAuthThrottle } from "../lib/authThrottle.js";
import { hashEnrollmentToken, isWellFormedEnrollmentToken } from "../lib/enrollment.js";
import { requireAuth } from "../middleware/requireAuth.js";
import { rateLimit } from "../middleware/rateLimit.js";

// In-memory burst limiters (per process). Identity keys are canonicalized
// exactly as the routes' own zod schemas canonicalize them, so case and
// whitespace variants of one email share a bucket. The authoritative,
// persistent per-account budget for guessable factors is authThrottle.
const emailIdentity = (req: Request) => normalizeEmail(req.body?.email);
const loginAttemptLimit = rateLimit({ max: 5, windowMs: 5 * 60 * 1000, identity: emailIdentity });
const fallbackIpLimit = rateLimit({ max: 50, windowMs: 15 * 60 * 1000 });
const registrationLimit = rateLimit({ max: 10, windowMs: 15 * 60 * 1000, identity: emailIdentity });
const enrollmentLimit = rateLimit({ max: 20, windowMs: 15 * 60 * 1000 });
const loginOptionsLimit = rateLimit({ max: 20, windowMs: 5 * 60 * 1000, identity: emailIdentity });

export const authRouter = Router();

const ACCESS_COOKIE = "accessToken";
const REFRESH_COOKIE = "refreshToken";
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

const emailSchema = z.string().trim().toLowerCase().email();

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

/**
 * Creates the Session row inside the caller's transaction (so the login's
 * audit event commits atomically with it) and returns the tokens to set as
 * cookies once that transaction has committed.
 */
async function createSession(tx: Prisma.TransactionClient, userId: string, deviceId: string) {
  // The token and database state must agree exactly from the very first
  // moment a session exists: generate the initial refresh jti, write it as
  // Session.currentRefreshTokenId in the same create call, then sign the
  // refresh JWT carrying that identical jti -- never a session with no jti
  // yet, never a token whose jti isn't already the one on record.
  const refreshTokenId = generateRefreshTokenId();
  const session = await tx.session.create({
    data: {
      userId,
      deviceId,
      trustLevel: 100,
      expiresAt: new Date(Date.now() + SESSION_TTL_MS),
      currentRefreshTokenId: refreshTokenId,
    },
  });
  const accessToken = signAccessToken({ sub: userId, sessionId: session.id });
  const refreshToken = signRefreshToken({ sub: userId, sessionId: session.id }, refreshTokenId);
  return { session, accessToken, refreshToken };
}

function publicUser(user: { id: string; email: string; name: string; role: string }) {
  return { id: user.id, email: user.email, name: user.name, role: user.role };
}

function isUniqueViolation(err: unknown): boolean {
  if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") return true;
  return err instanceof Error && /\b23505\b/.test(err.message);
}

// --- Registration and enrollment ---
//
// Security model (P0-1): knowing an account's email must never be enough to
// attach a credential to it.
//
//   * Existing accounts (including every privileged one) can only gain a
//     passkey by redeeming a single-use, expiring enrollment token issued by
//     a super admin after a fresh passkey step-up (POST /users/:id/enrollment-token),
//     or by the operator bootstrap script (scripts/create-enrollment-token.ts).
//   * Open self-registration is OFF unless ALLOW_OPEN_REGISTRATION=true. Even
//     then it can only create a brand-new MEMBER account for an email that
//     does not exist yet; the user row is created only after the WebAuthn
//     ceremony verifies, and an existing email is refused outright.

function openRegistrationEnabled(): boolean {
  return process.env.ALLOW_OPEN_REGISTRATION === "true";
}

const registerOptionsSchema = z.object({
  email: emailSchema,
  name: z.string().trim().min(1).max(120),
});

interface PendingRegistration {
  challenge: string;
  userId: string;
  name: string;
}

authRouter.post("/register/options", registrationLimit, async (req, res) => {
  if (!openRegistrationEnabled()) {
    res.status(403).json({ error: "Self-registration is disabled. Ask an administrator for an enrollment link." });
    return;
  }
  const parsed = registerOptionsSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }
  const { email, name } = parsed.data;

  const existing = await prisma.user.findUnique({ where: { email }, select: { id: true } });
  if (existing) {
    // Never hand out a registration ceremony for an existing account.
    res.status(409).json({
      error: "An account with this email already exists. Adding a passkey to it requires an enrollment link from an administrator.",
    });
    return;
  }

  // Pre-allocated id used as the WebAuthn user handle; nothing is persisted
  // until /register/verify succeeds.
  const userId = randomUUID();
  const options = await generateRegistrationOptions({
    rpName: env.rpName,
    rpID: env.rpId,
    userID: isoUint8Array.fromUTF8String(userId),
    userName: email,
    userDisplayName: name,
    attestationType: "none",
    authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
  });

  const pending: PendingRegistration = { challenge: options.challenge, userId, name };
  setChallenge(`register:${email}`, JSON.stringify(pending));
  res.json(options);
});

const registerVerifySchema = z.object({
  email: emailSchema,
  deviceLabel: z.string().trim().min(1).max(60).optional(),
  response: z.custom<RegistrationResponseJSON>((v) => typeof v === "object" && v !== null),
});

authRouter.post("/register/verify", registrationLimit, async (req, res) => {
  if (!openRegistrationEnabled()) {
    res.status(403).json({ error: "Self-registration is disabled. Ask an administrator for an enrollment link." });
    return;
  }
  const parsed = registerVerifySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }
  const { email, response, deviceLabel } = parsed.data;

  const pendingRaw = takeChallenge(`register:${email}`);
  if (!pendingRaw) {
    res.status(400).json({ error: "Registration challenge expired, please restart" });
    return;
  }
  const pending = JSON.parse(pendingRaw) as PendingRegistration;

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: pending.challenge,
      expectedOrigin: env.rpOrigin,
      expectedRPID: env.rpId,
      requireUserVerification: true,
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
  try {
    await auditedTransaction(async (tx) => {
      // Unique(email) makes this fail if the account appeared in the
      // meantime -- a concurrent registration or an admin invite -- so this
      // path can still never attach a credential to an existing account.
      const user = await tx.user.create({ data: { id: pending.userId, email, name: pending.name } });
      await tx.credential.create({
        data: {
          userId: user.id,
          type: "PASSKEY",
          credentialId: credentialID,
          publicKey: isoBase64URL.fromBuffer(credentialPublicKey),
          counter: BigInt(counter),
          deviceLabel: deviceLabel ?? "Passkey",
        },
      });
      await appendAuditLog(tx, {
        entityType: "User",
        entityId: user.id,
        event: "USER_SELF_REGISTERED",
        actorId: user.id,
        metadata: { role: user.role },
      });
      await appendAuditLog(tx, {
        entityType: "User",
        entityId: user.id,
        event: "PASSKEY_REGISTERED",
        actorId: user.id,
        metadata: { deviceLabel: deviceLabel ?? "Passkey", method: "open_registration" },
      });
    });
  } catch (err) {
    if (isUniqueViolation(err)) {
      res.status(409).json({ error: "Registration could not be completed for this email" });
      return;
    }
    throw err;
  }

  res.json({ verified: true });
});

const enrollmentTokenSchema = z.string().refine(isWellFormedEnrollmentToken, "Invalid enrollment token");

async function findRedeemableEnrollment(token: string) {
  const record = await prisma.enrollmentToken.findUnique({
    where: { tokenHash: hashEnrollmentToken(token) },
    include: { user: { include: { credentials: true } } },
  });
  if (!record || record.usedAt || record.revokedAt || record.expiresAt <= new Date()) return null;
  if (record.user.status !== "ACTIVE") return null;
  return record;
}

authRouter.post("/enroll/options", enrollmentLimit, async (req, res) => {
  const parsed = z.object({ token: enrollmentTokenSchema }).safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid or expired enrollment link" });
    return;
  }
  const record = await findRedeemableEnrollment(parsed.data.token);
  if (!record) {
    res.status(400).json({ error: "Invalid or expired enrollment link" });
    return;
  }

  const options = await generateRegistrationOptions({
    rpName: env.rpName,
    rpID: env.rpId,
    userID: isoUint8Array.fromUTF8String(record.user.id),
    userName: record.user.email,
    userDisplayName: record.user.name,
    attestationType: "none",
    excludeCredentials: record.user.credentials
      .filter((c) => c.type === "PASSKEY" && c.credentialId)
      .map((c) => ({ id: c.credentialId! })),
    authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
  });

  setChallenge(`enroll:${record.id}`, options.challenge);
  res.json({ options, account: { email: record.user.email, name: record.user.name } });
});

const enrollVerifySchema = z.object({
  token: enrollmentTokenSchema,
  deviceLabel: z.string().trim().min(1).max(60).optional(),
  response: z.custom<RegistrationResponseJSON>((v) => typeof v === "object" && v !== null),
});

authRouter.post("/enroll/verify", enrollmentLimit, async (req, res) => {
  const parsed = enrollVerifySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid or expired enrollment link" });
    return;
  }
  const { token, response, deviceLabel } = parsed.data;

  const record = await findRedeemableEnrollment(token);
  if (!record) {
    res.status(400).json({ error: "Invalid or expired enrollment link" });
    return;
  }
  const expectedChallenge = takeChallenge(`enroll:${record.id}`);
  if (!expectedChallenge) {
    res.status(400).json({ error: "Enrollment challenge expired, please restart" });
    return;
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: env.rpOrigin,
      expectedRPID: env.rpId,
      requireUserVerification: true,
    });
  } catch {
    res.status(400).json({ error: "Enrollment verification failed" });
    return;
  }
  if (!verification.verified || !verification.registrationInfo) {
    res.status(400).json({ error: "Enrollment verification failed" });
    return;
  }

  const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
  try {
    const outcome = await auditedTransaction(async (tx) => {
      // Atomic single-use consumption: exactly one concurrent redemption wins.
      const consumed = await tx.enrollmentToken.updateMany({
        where: { id: record.id, usedAt: null, revokedAt: null, expiresAt: { gt: new Date() } },
        data: { usedAt: new Date() },
      });
      if (consumed.count !== 1) return "CONSUMED" as const;
      const target = await tx.user.findUnique({ where: { id: record.userId }, select: { status: true } });
      if (target?.status !== "ACTIVE") return "INACTIVE" as const;

      await tx.credential.create({
        data: {
          userId: record.userId,
          type: "PASSKEY",
          credentialId: credentialID,
          publicKey: isoBase64URL.fromBuffer(credentialPublicKey),
          counter: BigInt(counter),
          deviceLabel: deviceLabel ?? "Passkey",
        },
      });
      await appendAuditLog(tx, {
        entityType: "User",
        entityId: record.userId,
        event: "PASSKEY_REGISTERED",
        actorId: record.userId,
        metadata: { deviceLabel: deviceLabel ?? "Passkey", method: "enrollment_token", enrollmentTokenId: record.id },
      });
      return "OK" as const;
    });
    if (outcome !== "OK") {
      res.status(400).json({ error: "Invalid or expired enrollment link" });
      return;
    }
  } catch (err) {
    if (isUniqueViolation(err)) {
      res.status(409).json({ error: "This passkey is already registered" });
      return;
    }
    throw err;
  }

  res.json({ verified: true });
});

// --- Login ---

/** Stable per-email fake credential id, derived with a server secret so it cannot be precomputed. */
function decoyCredentialId(email: string): string {
  return createHmac("sha256", env.jwtAccessSecret).update(`login-decoy:${email}`).digest("base64url");
}

const loginOptionsSchema = z.object({ email: emailSchema });

authRouter.post("/login/options", loginOptionsLimit, async (req, res) => {
  const parsed = loginOptionsSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }
  const { email } = parsed.data;

  const user = await prisma.user.findUnique({ where: { email }, include: { credentials: true } });
  const passkeys = user?.credentials.filter((c) => c.type === "PASSKEY" && c.credentialId) ?? [];

  // An unknown email and a known account without a passkey must be
  // indistinguishable from a real one, so this endpoint cannot be used to
  // discover which addresses have accounts. They get options naming a
  // decoy credential that is stable per email (so repeated requests agree);
  // no authenticator holds it, so the ceremony simply fails at verify with the
  // same generic message as any other failure.
  const allowCredentials =
    user && passkeys.length > 0 ? passkeys.map((c) => ({ id: c.credentialId! })) : [{ id: decoyCredentialId(email) }];

  const options = await generateAuthenticationOptions({
    rpID: env.rpId,
    // Matches what /login/verify enforces (userVerification is required there).
    userVerification: "required",
    allowCredentials,
  });

  setChallenge(`login:${email}`, options.challenge);
  res.json(options);
});

const loginVerifySchema = z.object({
  email: emailSchema,
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
    res.status(400).json({ error: "Login verification failed" });
    return;
  }

  const result = await verifyPasskeyAssertion({ credentials: user.credentials, response, expectedChallenge });
  if (!result.ok) {
    // One message for every failure, so the response never reveals whether the
    // credential, the account or the signature was the problem.
    res.status(400).json({ error: "Login verification failed" });
    return;
  }

  // Status is checked only after the passkey proves possession, so the
  // response doesn't reveal account state to someone without the credential.
  if (user.status !== "ACTIVE") {
    res.status(403).json({ error: "This account is not active" });
    return;
  }

  const issued = await auditedTransaction(async (tx) => {
    await tx.credential.update({
      where: { id: result.credential.id },
      data: { counter: BigInt(result.newCounter), lastUsedAt: new Date() },
    });
    const created = await createSession(tx, user.id, result.credential.id);
    await appendAuditLog(tx, {
      entityType: "Session",
      entityId: created.session.id,
      event: "LOGIN_SUCCESS",
      actorId: user.id,
      metadata: { deviceId: result.credential.id },
    });
    return created;
  });
  setAuthCookies(res, issued.accessToken, issued.refreshToken);

  res.json({ verified: true, user: publicUser(user) });
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

// Enrolling TOTP writes a brand-new, fully independent login path (just
// like minting recovery codes) and, on re-enrollment, deletes whatever TOTP
// credential the real user already had -- so a stolen session cookie alone
// must not be enough to install it. A fresh passkey signature is required
// immediately before the write, not just a valid session.
authRouter.post("/totp/verify/options", requireAuth, async (req, res) => {
  const options = await beginStepUp(req.user!.id, "totp-enroll");
  if (!options) {
    res.status(400).json({ error: "No passkeys registered for this account" });
    return;
  }
  res.json(options);
});

const totpVerifySchema = z.object({
  token: z.string().trim().length(6),
  response: z.custom<AuthenticationResponseJSON>((v) => typeof v === "object" && v !== null),
});

authRouter.post("/totp/verify", requireAuth, async (req, res) => {
  const parsed = totpVerifySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }
  const { token, response } = parsed.data;

  const secret = takeChallenge(`totp-setup:${req.user!.id}`);
  if (!secret) {
    res.status(400).json({ error: "TOTP setup expired, please restart" });
    return;
  }

  const stepUp = await verifyStepUp(req.user!.id, "totp-enroll", response);
  if (!stepUp.ok) {
    res.status(stepUp.status).json({ error: stepUp.error });
    return;
  }

  const step = matchTotpStep(token, secret);
  if (step === null) {
    res.status(400).json({ error: "Invalid code" });
    return;
  }

  await auditedTransaction(async (tx) => {
    await recordStepUpCounter(tx, stepUp);
    // Replace, don't accumulate: re-enrolling should leave exactly one active
    // TOTP credential, otherwise login can end up checking against a stale
    // secret that no longer matches what's in the user's authenticator app.
    await tx.credential.deleteMany({ where: { userId: req.user!.id, type: "TOTP" } });
    await tx.credential.create({
      data: {
        userId: req.user!.id,
        type: "TOTP",
        secret: encryptTotpSecret(secret),
        deviceLabel: "Authenticator app",
        // The confirmation code has been used; it can't be replayed to sign in.
        totpLastUsedStep: BigInt(step),
      },
    });
    await appendAuditLog(tx, {
      entityType: "User",
      entityId: req.user!.id,
      event: "TOTP_ENROLLED",
      actorId: req.user!.id,
    });
  });

  res.json({ verified: true });
});

const totpLoginSchema = z.object({
  email: emailSchema,
  token: z.string().trim().regex(/^\d{6}$/),
});

function rejectThrottled(res: Response, retryAfterMs: number): void {
  res.setHeader("Retry-After", String(Math.ceil(retryAfterMs / 1000)));
  res.status(429).json({ error: "Too many attempts for this account. Try again later or sign in with your passkey." });
}

async function recordFallbackFailure(userId: string, event: string, reason: string): Promise<void> {
  await auditedTransaction((tx) =>
    appendAuditLog(tx, { entityType: "User", entityId: userId, event, metadata: { reason } }),
  );
}

authRouter.post("/login/totp", fallbackIpLimit, loginAttemptLimit, async (req, res) => {
  const parsed = totpLoginSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }
  const { email, token } = parsed.data;

  // Reserve an attempt against the persistent per-account budget before any
  // secret is checked, so concurrent guesses can't race past the limit.
  const subject = fallbackSubject(email);
  const throttle = await reserveAuthAttempt(subject);
  if (!throttle.allowed) {
    rejectThrottled(res, throttle.retryAfterMs);
    return;
  }

  const user = await prisma.user.findUnique({ where: { email }, include: { credentials: true } });
  const totpCredential = user?.credentials.find((c) => c.type === "TOTP" && c.secret);
  if (!user || !totpCredential || !totpCredential.secret) {
    res.status(400).json({ error: "Invalid email or code" });
    return;
  }

  if (!user.totpLoginEnabled) {
    res.status(403).json({ error: "TOTP login is disabled for this account" });
    return;
  }

  let decryptedSecret: string;
  try {
    decryptedSecret = decryptTotpSecret(totpCredential.secret);
  } catch {
    // A malformed/corrupt stored secret should fail the same way a wrong
    // code does, not crash the request -- there's no legitimate submitted
    // code that could ever satisfy a credential we can't decrypt anyway.
    res.status(400).json({ error: "Invalid email or code" });
    return;
  }

  const step = matchTotpStep(token, decryptedSecret);
  if (step === null) {
    await recordFallbackFailure(user.id, "LOGIN_FAILED_TOTP", "invalid_code");
    res.status(400).json({ error: "Invalid email or code" });
    return;
  }

  if (user.status !== "ACTIVE") {
    res.status(403).json({ error: "This account is not active" });
    return;
  }

  const issued = await auditedTransaction(async (tx) => {
    // Replay protection: accept only a strictly later time step than the
    // last accepted one. Conditional update, so two concurrent submissions of
    // the same code can't both win.
    const accepted = await tx.credential.updateMany({
      where: {
        id: totpCredential.id,
        OR: [{ totpLastUsedStep: null }, { totpLastUsedStep: { lt: BigInt(step) } }],
      },
      data: { totpLastUsedStep: BigInt(step), lastUsedAt: new Date() },
    });
    if (accepted.count !== 1) return null;
    await resetAuthThrottle(tx, subject);
    const created = await createSession(tx, user.id, totpCredential.id);
    await appendAuditLog(tx, {
      entityType: "Session",
      entityId: created.session.id,
      event: "LOGIN_SUCCESS_TOTP",
      actorId: user.id,
      metadata: { deviceId: totpCredential.id },
    });
    return created;
  });

  if (!issued) {
    await recordFallbackFailure(user.id, "LOGIN_FAILED_TOTP", "code_replayed");
    res.status(400).json({ error: "This code has already been used. Wait for the next code." });
    return;
  }
  setAuthCookies(res, issued.accessToken, issued.refreshToken);

  res.json({ verified: true, user: publicUser(user) });
});

// --- Recovery codes ---
// Single-use codes for when neither a passkey device nor an authenticator app
// is available. Each code is its own Credential row (hashed, never stored
// plaintext) so redemption is just "delete the matching row" — no separate
// used/unused flag to keep in sync.

const RECOVERY_CODE_COUNT = 10;
// Crockford base32 (no I, L, O, U): unambiguous when read back by hand.
const RECOVERY_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const RECOVERY_CODE_LENGTH = 16; // 16 x 5 bits = 80 bits of entropy per code

/** Canonical form used for hashing: uppercase, separators removed. */
export function canonicalRecoveryCode(input: string): string {
  return input.toUpperCase().replace(/[\s-]/g, "");
}

function generateRecoveryCode(): string {
  let raw = "";
  for (let i = 0; i < RECOVERY_CODE_LENGTH; i++) raw += RECOVERY_ALPHABET[randomInt(0, RECOVERY_ALPHABET.length)];
  return raw.match(/.{4}/g)!.join("-");
}

function generateRecoveryCodeBatch(count: number): string[] {
  const codes = new Set<string>();
  while (codes.size < count) codes.add(generateRecoveryCode());
  return [...codes];
}

// Regenerating recovery codes is step-up gated: it must be preceded by a fresh
// passkey signature, not just a valid session cookie. Without this, a stolen
// access token would let an attacker silently mint a brand-new set of recovery
// codes as a persistent backdoor.
authRouter.post("/recovery-codes/options", requireAuth, async (req, res) => {
  const options = await beginStepUp(req.user!.id, "recovery-codes");
  if (!options) {
    res.status(400).json({ error: "No passkeys registered for this account" });
    return;
  }
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

  const stepUp = await verifyStepUp(req.user!.id, "recovery-codes", parsed.data.response);
  if (!stepUp.ok) {
    res.status(stepUp.status).json({ error: stepUp.error });
    return;
  }

  const codes = generateRecoveryCodeBatch(RECOVERY_CODE_COUNT);

  await auditedTransaction(async (tx) => {
    await recordStepUpCounter(tx, stepUp);
    await tx.credential.deleteMany({ where: { userId: req.user!.id, type: "RECOVERY_CODE" } });
    await tx.credential.createMany({
      data: codes.map((code) => ({
        userId: req.user!.id,
        type: "RECOVERY_CODE" as const,
        secret: hashSecret(canonicalRecoveryCode(code)),
        deviceLabel: "Recovery code",
      })),
    });
    await appendAuditLog(tx, {
      entityType: "User",
      entityId: req.user!.id,
      event: "RECOVERY_CODES_GENERATED",
      actorId: req.user!.id,
      metadata: { count: codes.length },
    });
  });

  // Codes are only ever returned in plaintext here — the DB only ever holds hashes.
  res.json({ codes });
});

const recoveryLoginSchema = z.object({
  email: emailSchema,
  code: z.string().trim().min(1).max(64),
});

authRouter.post("/login/recovery-code", fallbackIpLimit, loginAttemptLimit, async (req, res) => {
  const parsed = recoveryLoginSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request", issues: parsed.error.issues });
    return;
  }
  const { email, code } = parsed.data;

  const subject = fallbackSubject(email);
  const throttle = await reserveAuthAttempt(subject);
  if (!throttle.allowed) {
    rejectThrottled(res, throttle.retryAfterMs);
    return;
  }

  const user = await prisma.user.findUnique({ where: { email }, include: { credentials: true } });
  if (user && !user.recoveryCodeLoginEnabled) {
    res.status(403).json({ error: "Recovery-code login is disabled for this account" });
    return;
  }
  // Current codes are hashed in canonical form; codes issued before the
  // format change were hashed exactly as displayed, so accept either.
  const candidates = [...new Set([canonicalRecoveryCode(code), code])];
  const match = user?.credentials.find(
    (c) => c.type === "RECOVERY_CODE" && c.secret && candidates.some((candidate) => verifySecret(candidate, c.secret!)),
  );
  if (!user || !match) {
    if (user) await recordFallbackFailure(user.id, "LOGIN_FAILED_RECOVERY_CODE", "invalid_code");
    res.status(400).json({ error: "Invalid or already-used recovery code" });
    return;
  }

  if (user.status !== "ACTIVE") {
    res.status(403).json({ error: "This account is not active" });
    return;
  }

  const issued = await auditedTransaction(async (tx) => {
    // Single-use under concurrency: only the transaction that actually
    // deletes the row may sign in with it.
    const redeemed = await tx.credential.deleteMany({ where: { id: match.id, type: "RECOVERY_CODE" } });
    if (redeemed.count !== 1) return null;
    await resetAuthThrottle(tx, subject);
    const created = await createSession(tx, user.id, match.id);
    await appendAuditLog(tx, {
      entityType: "Session",
      entityId: created.session.id,
      event: "LOGIN_SUCCESS_RECOVERY_CODE",
      actorId: user.id,
    });
    return created;
  });

  if (!issued) {
    res.status(400).json({ error: "Invalid or already-used recovery code" });
    return;
  }
  setAuthCookies(res, issued.accessToken, issued.refreshToken);

  res.json({ verified: true, user: publicUser(user) });
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

  const session = await prisma.session.findUnique({
    where: { id: payload.sessionId },
    include: { user: { select: { status: true } } },
  });
  if (!session || session.expiresAt < new Date()) {
    res.status(401).json({ error: "Session expired" });
    return;
  }

  // A disabled or suspended account can't extend a session, even with a
  // perfectly valid, current refresh token. (Changing status also deletes the
  // account's sessions; this keeps the rule true on its own.)
  if (session.user.status !== "ACTIVE") {
    res.status(401).json({ error: "Session expired" });
    return;
  }

  // Defense-in-depth: the session this token names must actually belong to
  // the user the token claims to be. A mismatch here isn't treated as
  // evidence of refresh-token replay against *this* session -- it doesn't
  // rotate anything and doesn't revoke the session -- since by itself it
  // says nothing about this session's own token history, only that the
  // presented token's sessionId/sub pairing doesn't line up with reality
  // (which a valid signature alone can't catch, since both are just claims
  // inside the same signed payload).
  if (payload.sub !== session.userId) {
    res.status(401).json({ error: "Invalid or expired refresh token" });
    return;
  }

  // P0-4: rotate the refresh token before doing anything else. This is an
  // atomic compare-and-swap against Session.currentRefreshTokenId (see
  // server/src/lib/refreshRotation.ts for the full rotate/grace/replay
  // state machine) -- outcome "rotated" or "grace" both mean this request
  // is legitimate and should proceed exactly as a refresh always has;
  // "replay" means the presented token was reused outside the grace window
  // and the session has just been revoked; "not_found" means the session
  // was removed by a concurrent replay detection for the same race.
  const newRefreshTokenId = generateRefreshTokenId();
  const rotation = await rotateRefreshToken(session.id, payload.jti, newRefreshTokenId);

  if (rotation.outcome === "not_found") {
    res.status(401).json({ error: "Session expired" });
    return;
  }
  if (rotation.outcome === "replay") {
    // Deliberately more specific than a bare "Unauthorized": this category
    // of failure (not "no session", not "bad signature") is useful for a
    // legitimate user to recognize if an unlucky grace-window miss ever
    // bumps them, without revealing the jti, token contents, or any other
    // session internals -- the message names only the general condition.
    res.status(401).json({ error: "Refresh token reuse detected" });
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
  const RECOVERY_PER_CHECKIN = 5;
  const decayedTrust = decayedTrustLevel(session);
  // Session.trustLevel is an Int column -- round explicitly rather than
  // letting Postgres truncate a fractional value silently, so the number
  // returned in this response always matches exactly what gets persisted.
  const trustLevel = Math.round(Math.min(100, decayedTrust + RECOVERY_PER_CHECKIN));

  // updateMany (not update): the session may have been revoked between the
  // rotation above and this write (logout, admin disable, a concurrent
  // replay detection). That must end the refresh as unauthenticated, not
  // surface as a 500 -- and must never re-issue cookies for a dead session.
  const touched = await prisma.session.updateMany({
    where: { id: session.id },
    data: { trustLevel, lastVerifiedAt: new Date() },
  });
  if (touched.count !== 1) {
    res.status(401).json({ error: "Session expired" });
    return;
  }

  const accessToken = signAccessToken({ sub: payload.sub, sessionId: session.id });
  const refreshToken = signRefreshToken({ sub: payload.sub, sessionId: session.id }, rotation.jti);
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
    status: user.status,
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
    const updated = await auditedTransaction(async (tx) => {
      const result = await tx.user.update({
        where: { id: user.id },
        data: Object.fromEntries(changes.map((change) => [change.field, change.newValue])),
      });
      for (const change of changes) {
        await appendAuditLog(tx, {
          entityType: "User",
          entityId: user.id,
          event: "auth_preference_changed",
          actorId: user.id,
          metadata: change,
        });
      }
      return result;
    });

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
  await auditedTransaction(async (tx) => {
    const removed = await tx.session.deleteMany({ where: { id: req.user!.sessionId } });
    if (removed.count === 1) {
      await appendAuditLog(tx, {
        entityType: "Session",
        entityId: req.user!.sessionId,
        event: "LOGOUT",
        actorId: req.user!.id,
      });
    }
  });
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

  await auditedTransaction(async (tx) => {
    const removed = await tx.session.deleteMany({ where: { id: session.id, userId: req.user!.id } });
    if (removed.count === 1) {
      await appendAuditLog(tx, {
        entityType: "Session",
        entityId: session.id,
        event: "SESSION_REVOKED",
        actorId: req.user!.id,
      });
    }
  });

  if (session.id === req.user!.sessionId) {
    res.clearCookie(ACCESS_COOKIE);
    res.clearCookie(REFRESH_COOKIE);
  }

  res.json({ revoked: true });
});
