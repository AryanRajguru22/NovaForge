import { describe, it, expect } from "vitest";
import { assertProductionConfiguration } from "../src/lib/env.js";

// A fully valid production configuration; each test breaks exactly one thing.
const good = (): NodeJS.ProcessEnv => ({
  NODE_ENV: "production",
  JWT_ACCESS_SECRET: "a".repeat(20) + "Zx9!kQ" + "b".repeat(20),
  JWT_REFRESH_SECRET: "c".repeat(20) + "Qm4#vT" + "d".repeat(20),
  TOTP_ENCRYPTION_KEY: "e".repeat(20) + "Lp7$wN" + "f".repeat(20),
  IDENTITY_SIGNING_PRIVATE_KEY: "-----BEGIN PRIVATE KEY-----\nplaceholder\n-----END PRIVATE KEY-----",
  IDENTITY_SIGNING_KEY_ID: "nf-test",
  IDENTITY_ISSUER: "https://nova.example.com",
  RP_ORIGIN: "https://nova.example.com",
});

describe("production configuration check", () => {
  it("accepts a complete, non-placeholder configuration", () => {
    expect(() => assertProductionConfiguration(good())).not.toThrow();
  });

  it("does nothing outside production, so local development keeps its placeholders", () => {
    expect(() => assertProductionConfiguration({ NODE_ENV: "development", JWT_ACCESS_SECRET: "change-me" })).not.toThrow();
    expect(() => assertProductionConfiguration({})).not.toThrow();
  });

  for (const name of ["JWT_ACCESS_SECRET", "JWT_REFRESH_SECRET", "TOTP_ENCRYPTION_KEY"]) {
    it(`rejects ${name} when missing, short, or a placeholder`, () => {
      for (const bad of [undefined, "", "short", "change-me-" + "x".repeat(40), "the-example-value-" + "x".repeat(40), "x".repeat(40) + "password"]) {
        const env = good();
        if (bad === undefined) delete env[name];
        else env[name] = bad;
        expect(() => assertProductionConfiguration(env), `${name}=${JSON.stringify(bad)}`).toThrow(new RegExp(name));
      }
    });
  }

  it("rejects identical access and refresh secrets", () => {
    const env = good();
    env.JWT_REFRESH_SECRET = env.JWT_ACCESS_SECRET;
    expect(() => assertProductionConfiguration(env)).toThrow(/must differ/);
  });

  for (const name of ["IDENTITY_SIGNING_PRIVATE_KEY", "IDENTITY_SIGNING_KEY_ID", "IDENTITY_ISSUER", "RP_ORIGIN"]) {
    it(`requires ${name}`, () => {
      const env = good();
      delete env[name];
      expect(() => assertProductionConfiguration(env)).toThrow(new RegExp(name));
    });
  }

  it("reports every problem at once instead of one per restart", () => {
    let message = "";
    try {
      assertProductionConfiguration({ NODE_ENV: "production" });
    } catch (err) {
      message = (err as Error).message;
    }
    for (const name of ["JWT_ACCESS_SECRET", "JWT_REFRESH_SECRET", "TOTP_ENCRYPTION_KEY", "IDENTITY_SIGNING_PRIVATE_KEY", "IDENTITY_ISSUER"]) {
      expect(message).toContain(name);
    }
  });

  it("never echoes a secret value in its error", () => {
    const env = good();
    env.JWT_ACCESS_SECRET = "change-me-super-secret-value-that-must-not-leak-1234";
    try {
      assertProductionConfiguration(env);
      throw new Error("expected a throw");
    } catch (err) {
      expect((err as Error).message).not.toContain("must-not-leak");
    }
  });
});
