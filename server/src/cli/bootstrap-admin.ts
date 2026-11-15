// First-administrator bootstrap. Compiled into dist/ so it ships in the
// production image (the scripts/ directory does not), which means a fresh
// deployment can be brought up with one command and no database shell:
//
//   docker exec <container> node dist/cli/bootstrap-admin.js --email admin@example.com --name "Admin"
//   npm run bootstrap:admin -- --email admin@example.com --name "Admin"      (from server/, after npm run build)
//
// It creates the first SUPER_ADMIN account and prints a single-use enrollment
// link for registering that account's first passkey. There are no passwords.
//
// Safety properties:
//   * It refuses to run if any active SUPER_ADMIN already exists, so it cannot
//     be used later as a privilege-escalation path. (Operator recovery of an
//     existing account is scripts/create-enrollment-token.ts.)
//   * The check and the create happen in one transaction behind an advisory
//     lock, so two concurrent runs cannot each create an administrator.
//   * It never changes the role of an existing non-admin account.
//   * Everything it does is audited in the same transaction as the write.
//   * The enrollment token is printed once and only its hash is stored.
import { pathToFileURL } from "node:url";
import { Prisma, Role } from "@prisma/client";
import { prisma } from "../lib/prisma.js";
import { env } from "../lib/env.js";
import { appendAuditLog, auditedTransaction } from "../lib/audit.js";
import { issueEnrollmentToken } from "../lib/enrollment.js";

const BOOTSTRAP_LOCK_KEY = 727003;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export class BootstrapRefusedError extends Error {}

export interface BootstrapResult {
  userId: string;
  email: string;
  token: string;
  expiresAt: Date;
  createdAccount: boolean;
}

/** Core logic, run inside the caller's transaction. Exported for tests. */
export async function bootstrapFirstAdminInTransaction(
  tx: Prisma.TransactionClient,
  input: { email: string; name?: string },
): Promise<BootstrapResult> {
  const email = input.email.trim().toLowerCase();
  if (!EMAIL_PATTERN.test(email) || email.length > 254) throw new BootstrapRefusedError("A valid --email is required");

  await tx.$executeRaw`SELECT pg_advisory_xact_lock(${BOOTSTRAP_LOCK_KEY})`;

  const existingAdmins = await tx.user.count({ where: { role: Role.SUPER_ADMIN, status: "ACTIVE" } });
  if (existingAdmins > 0) {
    throw new BootstrapRefusedError(
      "An active SUPER_ADMIN already exists; bootstrap is only for an empty installation. " +
        "To recover an existing account use scripts/create-enrollment-token.ts.",
    );
  }

  let user = await tx.user.findUnique({ where: { email } });
  let createdAccount = false;
  if (user) {
    // A lock-out recovery (every super admin disabled) may promote an account
    // that already exists, but only if it is the account the operator named and
    // it is not itself disabled.
    if (user.status !== "ACTIVE") throw new BootstrapRefusedError(`Account ${email} is ${user.status}; it cannot be bootstrapped`);
    if (user.role !== Role.SUPER_ADMIN) {
      user = await tx.user.update({ where: { id: user.id }, data: { role: Role.SUPER_ADMIN } });
      await appendAuditLog(tx, {
        entityType: "User",
        entityId: user.id,
        event: "ROLE_CHANGED",
        metadata: { newRole: Role.SUPER_ADMIN, via: "bootstrap-admin" },
      });
    }
  } else {
    const name = input.name?.trim();
    if (!name) throw new BootstrapRefusedError("--name is required when creating the account");
    user = await tx.user.create({ data: { email, name, role: Role.SUPER_ADMIN } });
    createdAccount = true;
    await appendAuditLog(tx, {
      entityType: "User",
      entityId: user.id,
      event: "USER_CREATED_BY_OPERATOR",
      metadata: { email, role: Role.SUPER_ADMIN, via: "bootstrap-admin" },
    });
  }

  const issued = await issueEnrollmentToken(tx, { userId: user.id, createdById: null, reason: "bootstrap_admin" });
  return { userId: user.id, email, token: issued.token, expiresAt: issued.expiresAt, createdAccount };
}

export function bootstrapFirstAdmin(input: { email: string; name?: string }): Promise<BootstrapResult> {
  return auditedTransaction((tx) => bootstrapFirstAdminInTransaction(tx, input));
}

function readArg(name: string): string | undefined {
  const idx = process.argv.indexOf(`--${name}`);
  return idx !== -1 ? process.argv[idx + 1] : undefined;
}

async function main(): Promise<void> {
  const email = readArg("email");
  if (!email) {
    console.error('Usage: node dist/cli/bootstrap-admin.js --email <email> --name "<name>"');
    process.exitCode = 1;
    return;
  }
  const result = await bootstrapFirstAdmin({ email, name: readArg("name") });
  console.log(`${result.createdAccount ? "Created" : "Promoted"} SUPER_ADMIN account: ${result.email}`);
  console.log(`Link expires at: ${result.expiresAt.toISOString()} (single use)`);
  console.log("\nOpen this address in a browser to register the first passkey (shown once; treat it like a password):\n");
  console.log(`  ${env.rpOrigin.replace(/\/+$/, "")}/login?enroll=${result.token}\n`);
}

// Run only when executed directly, never when imported by a test.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main()
    .catch((err) => {
      console.error(err instanceof Error ? err.message : err);
      process.exitCode = 1;
    })
    .finally(() => prisma.$disconnect());
}
