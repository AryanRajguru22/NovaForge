import "dotenv/config";

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required env var: ${name}`);
  return value;
}

export const env = {
  port: Number(process.env.PORT ?? 4000),
  databaseUrl: required("DATABASE_URL"),
  jwtAccessSecret: required("JWT_ACCESS_SECRET"),
  jwtRefreshSecret: required("JWT_REFRESH_SECRET"),
  rpId: process.env.RP_ID ?? "localhost",
  rpName: process.env.RP_NAME ?? "NovaForge",
  rpOrigin: process.env.RP_ORIGIN ?? "http://localhost:5173",
};
