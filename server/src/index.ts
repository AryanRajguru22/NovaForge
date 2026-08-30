import { httpServer, io, initEscalationService, initSocketSecurity } from "./app.js";
import { env } from "./lib/env.js";

initEscalationService(io);
initSocketSecurity(io);

httpServer.listen(env.port, () => {
  console.log(`NovaForge server listening on :${env.port}`);
});
