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
  rpId: process.env.RP_ID ?? (renderExternalUrl ? new URL(renderExternalUrl).hostname : "localhost"),
  rpName: process.env.RP_NAME ?? "NovaForge",
  rpOrigin: process.env.RP_ORIGIN ?? renderExternalUrl ?? "http://localhost:5173",
};
