import { Router, type Response } from "express";
import { z } from "zod";
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
import { appendAuditLog } from "../lib/audit.js";
import { requireAuth } from "../middleware/requireAuth.js";

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

authRouter.post("/login/verify", async (req, res) => {
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
  const hoursSinceVerified = (Date.now() - session.lastVerifiedAt.getTime()) / 3_600_000;
  const trustLevel = Math.max(0, 100 - Math.floor(hoursSinceVerified) * 5);

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
  const user = await prisma.user.findUnique({ where: { id: req.user!.id } });
  if (!user) {
    res.status(404).json({ error: "User not found" });
    return;
  }
  res.json({ id: user.id, email: user.email, name: user.name, role: user.role });
});

authRouter.post("/logout", requireAuth, async (req, res) => {
  await prisma.session.delete({ where: { id: req.user!.sessionId } }).catch(() => undefined);
  res.clearCookie(ACCESS_COOKIE);
  res.clearCookie(REFRESH_COOKIE);
  res.json({ loggedOut: true });
});
