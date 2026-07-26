// Demo/ops utility -- NOT part of the running app. Backdates a user's most
// recently verified session's lastVerifiedAt, so the next call to
// POST /auth/session/refresh (which the client fires automatically on every
// page load, plus every 4 minutes) computes real trust decay against a real
// gap -- the same code path a genuine multi-hour outage would hit, without
// actually waiting hours. Useful for live-demoing the trust decay/recovery
// fix: back-date, reload the app once to see the decayed value, reload a
// few more times to watch it climb back gradually instead of snapping to
// 100.
//
// Usage:
//   npx tsx scripts/backdate-session.ts --email demo@example.com --hours 5
//   npx tsx scripts/backdate-session.ts --email demo@example.com --hours 5 --session <sessionId>
//
// Run against prod by pointing DATABASE_URL at it for just this command:
//   Bash:       DATABASE_URL="postgresql://...render.com/novaforge_db" npx tsx scripts/backdate-session.ts --email demo@example.com --hours 5
//   PowerShell: $env:DATABASE_URL="postgresql://...render.com/novaforge_db"; npx tsx scripts/backdate-session.ts --email demo@example.com --hours 5
import { prisma } from "../src/lib/prisma.js";

function readArg(name: string): string | undefined {
  const idx = process.argv.indexOf(`--${name}`);
  return idx !== -1 ? process.argv[idx + 1] : undefined;
}

async function main() {
  const email = readArg("email");
  const hoursArg = readArg("hours");
  const sessionId = readArg("session");

  if (!email || !hoursArg) {
    console.error("Usage: npx tsx scripts/backdate-session.ts --email <email> --hours <n> [--session <id>]");
    process.exit(1);
  }
  const hours = Number(hoursArg);
  if (!Number.isFinite(hours) || hours <= 0) {
    console.error("--hours must be a positive number");
    process.exit(1);
  }

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    console.error(`No user found with email ${email}`);
    process.exit(1);
  }

  const session = sessionId
    ? await prisma.session.findUnique({ where: { id: sessionId } })
    : await prisma.session.findFirst({
        where: { userId: user.id },
        orderBy: { lastVerifiedAt: "desc" },
      });

  if (!session || session.userId !== user.id) {
    console.error(sessionId ? `Session ${sessionId} not found for ${email}` : `${email} has no active sessions`);
    process.exit(1);
  }

  console.log("Before:");
  console.log("  session id:      ", session.id);
  console.log("  deviceId:        ", session.deviceId);
  console.log("  trustLevel:      ", session.trustLevel);
  console.log("  lastVerifiedAt:  ", session.lastVerifiedAt.toISOString());

  const newLastVerifiedAt = new Date(Date.now() - hours * 3_600_000);
  await prisma.session.update({
    where: { id: session.id },
    data: { lastVerifiedAt: newLastVerifiedAt },
  });

  console.log(`\nBackdated lastVerifiedAt by ${hours} hour(s).`);
  console.log("New lastVerifiedAt:", newLastVerifiedAt.toISOString());
  console.log("\nReload the app now (or wait for its next automatic session/refresh call)");
  console.log("to see the decayed trustLevel. Reload a few more times to watch it recover gradually.");

  await prisma.$disconnect();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
