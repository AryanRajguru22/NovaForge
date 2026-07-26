import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { env } from "./env.js";

// TOTP secrets are fundamentally different from passwords or recovery codes:
// verifying a submitted code requires the server to recompute
// HMAC(secret, counter) itself, so it must always be able to recover the
// *exact original secret* -- a one-way hash (what recovery codes correctly
// use, server/src/lib/hash.ts) would make every future login impossible to
// verify. The right tool here is reversible encryption at rest, with the key
// held outside the database (an env var, ideally a real secrets manager in
// a non-hobby deployment) -- so a stolen DB dump alone (a backup leak, an
// injection bug, a leaked connection string) doesn't hand over live,
// unlimited-use second-factor codes for every enrolled account. Previously
// this column held the raw base32 secret in plain text.
const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12; // 96-bit nonce, the AES-GCM standard/recommended size
const FORMAT_TAG = "gcm1"; // lets a future migration/rotation tell "already encrypted" from legacy plaintext

// TOTP_ENCRYPTION_KEY is an arbitrary-length secret (same pattern as
// JWT_ACCESS_SECRET/JWT_REFRESH_SECRET) -- hashed down to a fixed 32-byte
// AES-256 key. It's high-entropy by construction (a long random env value,
// not a human-chosen password), so a plain fast hash is appropriate here;
// this isn't password storage, there's no need for a slow/memory-hard KDF.
function deriveKey(): Buffer {
  return createHash("sha256").update(env.totpEncryptionKey).digest();
}

export function encryptTotpSecret(plaintext: string): string {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, deriveKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return [FORMAT_TAG, iv.toString("hex"), authTag.toString("hex"), ciphertext.toString("hex")].join(":");
}

export function decryptTotpSecret(stored: string): string {
  const parts = stored.split(":");
  if (parts.length !== 4 || parts[0] !== FORMAT_TAG) {
    throw new Error("TOTP secret is not in the expected encrypted format");
  }
  const [, ivHex, authTagHex, ciphertextHex] = parts;
  const decipher = createDecipheriv(ALGORITHM, deriveKey(), Buffer.from(ivHex, "hex"));
  decipher.setAuthTag(Buffer.from(authTagHex, "hex"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(ciphertextHex, "hex")),
    decipher.final(),
  ]);
  return plaintext.toString("utf8");
}
