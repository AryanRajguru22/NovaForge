import "dotenv/config";

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required env var: ${name}`);
  return value;
}

// Render injects RENDER_EXTERNAL_URL into every service automatically — used
// as a fallback so a deployed instance doesn't need RP_ID/RP_ORIGIN set by
// hand (and can't drift from the real assigned URL). Local/Docker Compose
// runs never have this var set, so the localhost defaults still apply there.
const renderExternalUrl = process.env.RENDER_EXTERNAL_URL;

export const env = {
  port: Number(process.env.PORT ?? 4000),
  databaseUrl: required("DATABASE_URL"),
  jwtAccessSecret: required("JWT_ACCESS_SECRET"),
  jwtRefreshSecret: required("JWT_REFRESH_SECRET"),
  totpEncryptionKey: required("TOTP_ENCRYPTION_KEY"),
  rpId: process.env.RP_ID ?? (renderExternalUrl ? new URL(renderExternalUrl).hostname : "localhost"),
  rpName: process.env.RP_NAME ?? "NovaForge",
  rpOrigin: process.env.RP_ORIGIN ?? renderExternalUrl ?? "http://localhost:5173",
};

// Production refuses to boot on development defaults. Placeholder secrets and an
// unconfigured signing key would otherwise turn into "works, but anyone can
// forge a session" -- failing loudly at startup is the safe behaviour.
export function assertProductionConfiguration(environment: NodeJS.ProcessEnv = process.env): void {
  if (environment.NODE_ENV !== "production") return;
  const problems: string[] = [];
  for (const name of ["JWT_ACCESS_SECRET", "JWT_REFRESH_SECRET", "TOTP_ENCRYPTION_KEY"]) {
    const value = environment[name] ?? "";
    if (value.length < 32 || /change-?me|example|secret$|password/i.test(value)) {
      problems.push(`${name} must be a random value of at least 32 characters (not a placeholder)`);
    }
  }
  if (environment.JWT_ACCESS_SECRET && environment.JWT_ACCESS_SECRET === environment.JWT_REFRESH_SECRET) {
    problems.push("JWT_ACCESS_SECRET and JWT_REFRESH_SECRET must differ");
  }
  if (!environment.IDENTITY_SIGNING_PRIVATE_KEY) problems.push("IDENTITY_SIGNING_PRIVATE_KEY (PKCS#8 P-256 PEM) is required");
  if (!environment.IDENTITY_SIGNING_KEY_ID) problems.push("IDENTITY_SIGNING_KEY_ID is required");
  if (!environment.IDENTITY_ISSUER) problems.push("IDENTITY_ISSUER (the public https origin of this service) is required");
  if (!environment.RP_ORIGIN && !process.env.RENDER_EXTERNAL_URL) problems.push("RP_ORIGIN is required");
  if (problems.length > 0) {
    throw new Error("Refusing to start in production with unsafe configuration:\n - " + problems.join("\n - "));
  }
}
