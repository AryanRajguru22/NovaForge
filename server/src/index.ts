import { httpServer, io, initEscalationService } from "./app.js";
import { env } from "./lib/env.js";

initEscalationService(io);

httpServer.listen(env.port, () => {
  console.log(`NovaForge server listening on :${env.port}`);
});
