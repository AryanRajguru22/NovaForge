import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

const KEY_LENGTH = 64;

/** Hashes a secret (recovery code, etc.) with a random salt using scrypt. */
export function hashSecret(secret: string): string {
  const salt = randomBytes(16).toString("hex");
  const derived = scryptSync(secret, salt, KEY_LENGTH).toString("hex");
  return `${salt}:${derived}`;
}

export function verifySecret(secret: string, hash: string): boolean {
  const [salt, derivedHex] = hash.split(":");
  if (!salt || !derivedHex) return false;
  const derived = scryptSync(secret, salt, KEY_LENGTH);
  const stored = Buffer.from(derivedHex, "hex");
  if (derived.length !== stored.length) return false;
  return timingSafeEqual(derived, stored);
}
