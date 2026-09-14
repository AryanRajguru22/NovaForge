// Operator utility -- NOT part of the running app. Creates (or finds) an
// account and issues a single-use enrollment token for it. This is how the
// first SUPER_ADMIN is bootstrapped, and how an operator with database access
// recovers an account whose every passkey is lost.
//
// The token is printed exactly once and is a bearer credential for adding a
// passkey to that account until it expires (24h) or is used: hand it over
// through a trusted channel, never paste it into tickets or chat.
//
// Usage:
//   npx tsx scripts/create-enrollment-token.ts --email admin@example.com --name "Admin" --role SUPER_ADMIN
//   npx tsx scripts/create-enrollment-token.ts --email existing@example.com
import { Role } from "@prisma/client";
import { prisma } from "../src/lib/prisma.js";
import { auditedTransaction, appendAuditLog } from "../src/lib/audit.js";
import { issueEnrollmentToken } from "../src/lib/enrollment.js";

function readArg(name: string): string | undefined {
  const idx = process.argv.indexOf(`--${name}`);
  return idx !== -1 ? process.argv[idx + 1] : undefined;
}

async function main() {
  const email = readArg("email")?.trim().toLowerCase();
  const name = readArg("name");
  const roleArg = readArg("role");
  if (!email) {
    console.error('Usage: npx tsx scripts/create-enrollment-token.ts --email <email> [--name "<name>"] [--role <ROLE>]');
    process.exit(1);
  }
  if (roleArg && !(roleArg in Role)) {
    console.error(`--role must be one of: ${Object.keys(Role).join(", ")}`);
    process.exit(1);
  }

  const result = await auditedTransaction(async (tx) => {
    let user = await tx.user.findUnique({ where: { email } });
    if (!user) {
      if (!name) throw new Error("--name is required when creating a new account");
      user = await tx.user.create({ data: { email, name, role: (roleArg as Role | undefined) ?? Role.MEMBER } });
      await appendAuditLog(tx, {
        entityType: "User",
        entityId: user.id,
        event: "USER_CREATED_BY_OPERATOR",
        metadata: { email, role: user.role },
      });
    } else if (roleArg && user.role !== roleArg) {
      throw new Error("Refusing to change an existing account's role from this script; use the admin UI");
    }
    if (user.status !== "ACTIVE") throw new Error(`Account is ${user.status}; reactivate it first`);
    const issued = await issueEnrollmentToken(tx, { userId: user.id, createdById: null, reason: "operator_script" });
    return { user, issued };
  });

  console.log(`Account:    ${result.user.email} (${result.user.role})`);
  console.log(`Expires at: ${result.issued.expiresAt.toISOString()}`);
  console.log(`Enrollment link path: /login?enroll=${result.issued.token}`);
  await prisma.$disconnect();
}

main().catch(async (err) => {
  console.error(err instanceof Error ? err.message : err);
  await prisma.$disconnect();
  process.exit(1);
});
