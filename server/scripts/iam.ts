// Operator CLI for the identity platform. Needs database access (DATABASE_URL),
// so it is the bootstrap / break-glass path; day-to-day administration is done
// in the console (/applications), which adds trust and passkey step-up checks.
//
//   npx tsx scripts/iam.ts register-pashupatastra --frontend-origin https://pashupatastra.example.com [--rotate-secret]
//   npx tsx scripts/iam.ts assign --app pashupatastra --email user@example.com --role authority [--resource "corridor/CORR-NDLS-AGC/*"]
//   npx tsx scripts/iam.ts dev-user --email dev@example.com --name "Dev User" [--role SUPER_ADMIN]   (refused in production)
//
// Secrets are printed exactly once, to stdout. Never commit or paste them.
import { authenticator } from "otplib";
import { Role } from "@prisma/client";
import { prisma } from "../src/lib/prisma.js";
import { encryptTotpSecret } from "../src/lib/totpSecretCrypto.js";
import { appendAuditLog, auditedTransaction } from "../src/lib/audit.js";
import { assignRoleByEmail, ensureApplication, pashupatastraSpec } from "../src/lib/oauth/provision.js";

function arg(name: string): string | undefined {
  const idx = process.argv.indexOf(`--${name}`);
  return idx !== -1 ? process.argv[idx + 1] : undefined;
}
const flag = (name: string) => process.argv.includes(`--${name}`);

async function main() {
  const command = process.argv[2];

  if (command === "register-pashupatastra") {
    const origin = arg("frontend-origin");
    if (!origin) throw new Error("--frontend-origin is required (the browser origin of the Pashupatastra console)");
    const url = new URL(origin);
    if (url.protocol !== "https:" && !["localhost", "127.0.0.1"].includes(url.hostname)) {
      throw new Error("The frontend origin must be https (http is only accepted for localhost)");
    }
    const result = await ensureApplication(pashupatastraSpec(url.origin), { rotateSecret: flag("rotate-secret"), issueSecretIfNone: true });
    console.log(result.created ? "Registered application 'pashupatastra'." : "Updated application 'pashupatastra'.");
    if (result.secret) {
      console.log("\nClient secret (shown once, store it in Pashupatastra's secret store):\n");
      console.log(`  PASHUPAT_AUTH_CLIENT_SECRET=${result.secret}\n`);
    } else {
      console.log("No new secret issued (use --rotate-secret to issue another).");
    }
    console.log("Pashupatastra settings:");
    console.log(`  PASHUPAT_AUTH_CLIENT_ID=pashupatastra`);
    console.log(`  PASHUPAT_AUTH_AUDIENCE=pashupatastra-api`);
    console.log(`  PASHUPAT_AUTH_REDIRECT_URI=${url.origin}/api/pp/auth/callback`);
    console.log(`  PASHUPAT_AUTH_FRONTEND_ORIGIN=${url.origin}`);
    return;
  }

  if (command === "assign") {
    const app = arg("app");
    const email = arg("email");
    const role = arg("role");
    if (!app || !email || !role) throw new Error("--app, --email and --role are required");
    await assignRoleByEmail({ clientId: app, email, roleKey: role, resource: arg("resource") });
    console.log(`Assigned ${role} in ${app} to ${email}${arg("resource") ? ` for ${arg("resource")}` : ""}.`);
    return;
  }

  if (command === "dev-user") {
    if (process.env.NODE_ENV === "production") throw new Error("dev-user is refused in production");
    const email = arg("email")?.trim().toLowerCase();
    const name = arg("name") ?? "Dev User";
    const role = (arg("role") as Role | undefined) ?? Role.MEMBER;
    if (!email) throw new Error("--email is required");
    if (!(role in Role)) throw new Error(`--role must be one of ${Object.keys(Role).join(", ")}`);
    const secret = authenticator.generateSecret();
    await auditedTransaction(async (tx) => {
      const user = await tx.user.upsert({ where: { email }, create: { email, name, role }, update: { name, role } });
      await tx.credential.deleteMany({ where: { userId: user.id, type: "TOTP" } });
      await tx.credential.create({ data: { userId: user.id, type: "TOTP", secret: encryptTotpSecret(secret), deviceLabel: "dev authenticator" } });
      await appendAuditLog(tx, { entityType: "User", entityId: user.id, event: "DEV_USER_PROVISIONED", metadata: { email, role } });
    });
    console.log(`Dev user ${email} (${role}). TOTP secret (base32): ${secret}`);
    console.log(`Current code: ${authenticator.generate(secret)}`);
    return;
  }

  console.log("Commands: register-pashupatastra | assign | dev-user (see the header of this file)");
  process.exitCode = 1;
}

main()
  .catch((err) => {
    console.error(err instanceof Error ? err.message : err);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
