import { randomBytes, timingSafeEqual } from "node:crypto";
import type { Request } from "express";
import type { OAuthClient } from "@prisma/client";
import { prisma } from "../prisma.js";
import { sha256Hex } from "../canonicalJson.js";

// Client authentication at the token, introspection and revocation endpoints
// (RFC 6749 section 2.3): client_secret_basic, client_secret_post, and "none"
// for public clients (only ever allowed at the token endpoint, where PKCE is
// their proof instead).
//
// Secrets are 256-bit random values; only their SHA-256 is stored (a fast
// hash is correct for a high-entropy random secret). Comparison is constant
// time and also runs for unknown clients, so timing does not reveal which
// client ids exist.

const SECRET_FORMAT = /^nfcs_[A-Za-z0-9_-]{43}$/;

export function generateClientSecret(): { secret: string; hash: string } {
  const secret = `nfcs_${randomBytes(32).toString("base64url")}`;
  return { secret, hash: sha256Hex(secret) };
}

export interface AuthenticatedClient {
  client: OAuthClient;
  method: "client_secret_basic" | "client_secret_post" | "none";
}

function formDecode(value: string): string {
  return decodeURIComponent(value.replace(/\+/g, " "));
}

function readCredentials(
  req: Request,
): { clientId: string; secret?: string; method: AuthenticatedClient["method"] } | null {
  const header = req.header("authorization");
  const body = (req.body ?? {}) as Record<string, unknown>;
  if (header?.toLowerCase().startsWith("basic ")) {
    // A request must use exactly one authentication method.
    if (typeof body.client_secret === "string") return null;
    try {
      const decoded = Buffer.from(header.slice(6).trim(), "base64").toString("utf8");
      const idx = decoded.indexOf(":");
      if (idx < 1) return null;
      return {
        clientId: formDecode(decoded.slice(0, idx)),
        secret: formDecode(decoded.slice(idx + 1)),
        method: "client_secret_basic",
      };
    } catch {
      return null;
    }
  }
  if (typeof body.client_id !== "string" || body.client_id.length === 0 || body.client_id.length > 200) return null;
  if (typeof body.client_secret === "string") {
    return { clientId: body.client_id, secret: body.client_secret, method: "client_secret_post" };
  }
  return { clientId: body.client_id, method: "none" };
}

/**
 * Authenticates the calling client, or returns null. A disabled client never
 * authenticates. Public clients may authenticate with method "none" only when
 * `allowPublic` is set.
 */
export async function authenticateClient(
  req: Request,
  opts: { allowPublic?: boolean } = {},
): Promise<AuthenticatedClient | null> {
  const creds = readCredentials(req);
  if (!creds) return null;
  const client = await prisma.oAuthClient.findUnique({ where: { clientId: creds.clientId }, include: { secrets: true } });

  if (creds.method === "none") {
    if (!opts.allowPublic || !client || client.type !== "PUBLIC" || client.status !== "ACTIVE") return null;
    return { client, method: "none" };
  }

  const presented = Buffer.from(sha256Hex(creds.secret ?? ""), "hex");
  const now = new Date();
  let matched: { id: string } | null = null;
  for (const secret of client?.secrets ?? []) {
    const expected = Buffer.from(secret.secretHash, "hex");
    const equal = expected.length === presented.length && timingSafeEqual(expected, presented);
    if (equal && !secret.revokedAt && (!secret.expiresAt || secret.expiresAt > now)) matched = secret;
  }
  if (
    !client ||
    client.type !== "CONFIDENTIAL" ||
    client.status !== "ACTIVE" ||
    !matched ||
    !SECRET_FORMAT.test(creds.secret ?? "")
  ) {
    return null;
  }
  await prisma.oAuthClientSecret.update({ where: { id: matched.id }, data: { lastUsedAt: now } });
  const { secrets: _omit, ...clientRow } = client;
  return { client: clientRow, method: creds.method };
}
