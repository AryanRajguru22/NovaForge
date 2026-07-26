import { describe, it, expect } from "vitest";
import { encryptTotpSecret, decryptTotpSecret } from "../src/lib/totpSecretCrypto.js";

describe("TOTP secret encryption at rest", () => {
  it("round-trips a secret through encrypt then decrypt", () => {
    const secret = "JBSWY3DPEHPK3PXP";
    const encrypted = encryptTotpSecret(secret);
    expect(decryptTotpSecret(encrypted)).toBe(secret);
  });

  it("never stores the plaintext secret as a substring of the encrypted value", () => {
    const secret = "JBSWY3DPEHPK3PXP";
    const encrypted = encryptTotpSecret(secret);
    expect(encrypted).not.toContain(secret);
  });

  it("produces a different ciphertext each time (random IV per encryption)", () => {
    const secret = "JBSWY3DPEHPK3PXP";
    const first = encryptTotpSecret(secret);
    const second = encryptTotpSecret(secret);
    expect(first).not.toBe(second);
    // ...but both still decrypt back to the same original secret.
    expect(decryptTotpSecret(first)).toBe(secret);
    expect(decryptTotpSecret(second)).toBe(secret);
  });

  it("rejects a tampered ciphertext instead of silently returning garbage", () => {
    const encrypted = encryptTotpSecret("JBSWY3DPEHPK3PXP");
    const parts = encrypted.split(":");
    // Flip a hex character in the ciphertext portion.
    const tamperedCiphertext = parts[3].replace(/^./, (c) => (c === "0" ? "1" : "0"));
    const tampered = [parts[0], parts[1], parts[2], tamperedCiphertext].join(":");
    expect(() => decryptTotpSecret(tampered)).toThrow();
  });

  it("rejects a legacy plaintext value that was never encrypted", () => {
    expect(() => decryptTotpSecret("JBSWY3DPEHPK3PXP")).toThrow(
      /not in the expected encrypted format/,
    );
  });
});
