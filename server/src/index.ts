import { httpServer, io, initEscalationService, initSocketSecurity, stopSocketSecurity } from "./app.js";
import { assertProductionConfiguration, env } from "./lib/env.js";
import { getIdentityKeyRing } from "./lib/identityKeys.js";
import { stopEscalationService } from "./lib/escalation.js";
import { prisma } from "./lib/prisma.js";

assertProductionConfiguration();
// Resolve the signing key now so a misconfigured key fails at boot, not on the first sign-in.
getIdentityKeyRing();

initEscalationService(io);
initSocketSecurity(io);

httpServer.listen(env.port, () => {
  console.log(`NovaForge server listening on :${env.port}`);
});

// Graceful shutdown (SIGTERM from Docker/Render, SIGINT from a terminal):
// stop the background timers, stop accepting connections and close sockets,
// let in-flight requests finish, then release the database pool. A hard
// deadline guarantees the process still exits if something refuses to drain.
const SHUTDOWN_DEADLINE_MS = 10_000;
let shuttingDown = false;

async function shutdown(signal: string): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`${signal} received: shutting down`);
  const deadline = setTimeout(() => {
    console.error("Shutdown deadline exceeded; forcing exit");
    process.exit(1);
  }, SHUTDOWN_DEADLINE_MS);
  deadline.unref();
  try {
    stopEscalationService();
    stopSocketSecurity();
    // Closes every Socket.io connection and the underlying HTTP server.
    await new Promise<void>((resolve) => io.close(() => resolve()));
    await prisma.$disconnect();
    process.exit(0);
  } catch (err) {
    console.error("Error during shutdown:", err instanceof Error ? err.message : err);
    process.exit(1);
  }
}

process.on("SIGTERM", () => void shutdown("SIGTERM"));
process.on("SIGINT", () => void shutdown("SIGINT"));
