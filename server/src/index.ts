import { httpServer, io, initEscalationService, initSocketSecurity } from "./app.js";
import { assertProductionConfiguration, env } from "./lib/env.js";
import { getIdentityKeyRing } from "./lib/identityKeys.js";

assertProductionConfiguration();
// Resolve the signing key now so a misconfigured key fails at boot, not on the first sign-in.
getIdentityKeyRing();

initEscalationService(io);
initSocketSecurity(io);

httpServer.listen(env.port, () => {
  console.log(`NovaForge server listening on :${env.port}`);
});
