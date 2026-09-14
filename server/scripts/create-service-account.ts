// Operator utility -- NOT part of the running app. Creates a service account
// for a relying service and issues its first credential. The credential is
// printed exactly once; store it in that service's secret manager.
//
// Usage:
//   npx tsx scripts/create-service-account.ts --name pashupatastra --audience pashupatastra --scopes identity:assert,identity:introspect
import { prisma } from "../src/lib/prisma.js";
import { auditedTransaction, appendAuditLog } from "../src/lib/audit.js";
import { SERVICE_SCOPES, createServiceCredential } from "../src/lib/serviceAuth.js";

function readArg(name: string): string | undefined {
  const idx = process.argv.indexOf(`--${name}`);
  return idx !== -1 ? process.argv[idx + 1] : undefined;
}

async function main() {
  const name = readArg("name");
  const audience = readArg("audience");
  const scopes = (readArg("scopes") ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  if (!name || !audience || scopes.length === 0) {
    console.error("Usage: npx tsx scripts/create-service-account.ts --name <name> --audience <aud> --scopes <scope,...>");
    process.exit(1);
  }
  const unknown = scopes.filter((s) => !(SERVICE_SCOPES as readonly string[]).includes(s));
  if (unknown.length > 0) {
    console.error(`Unknown scopes: ${unknown.join(", ")}. Allowed: ${SERVICE_SCOPES.join(", ")}`);
    process.exit(1);
  }

  const { account, credential } = await auditedTransaction(async (tx) => {
    const account = await tx.serviceAccount.create({ data: { name, audience, scopes } });
    const credential = await createServiceCredential(tx, account.id);
    await appendAuditLog(tx, {
      entityType: "ServiceAccount",
      entityId: account.id,
      event: "SERVICE_ACCOUNT_CREATED",
      metadata: { name, audience, scopes, credentialId: credential.credentialId, via: "operator_script" },
    });
    return { account, credential };
  });

  console.log(`Service account: ${account.name} (audience "${account.audience}")`);
  console.log(`Credential (shown once): ${credential.token}`);
  await prisma.$disconnect();
}

main().catch(async (err) => {
  console.error(err instanceof Error ? err.message : err);
  await prisma.$disconnect();
  process.exit(1);
});
