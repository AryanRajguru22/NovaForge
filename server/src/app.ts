import http from "node:http";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import express from "express";
// Must be imported before any router is created: it patches Express 4's
// Router so a rejected/thrown promise inside an async route handler is
// forwarded to the error-handling middleware below instead of becoming an
// unhandled rejection that crashes the whole process. Express 4 has no
// native support for this (Express 5 does) -- without it, any single
// uncaught error in any route takes down the entire server for every
// connected user, not just the one request that hit it, until Render
// notices the crash and restarts the container.
import "express-async-errors";
import cors from "cors";
import cookieParser from "cookie-parser";
import { Server as SocketIOServer } from "socket.io";
import { env } from "./lib/env.js";
import { authRouter } from "./routes/auth.js";
import { policiesRouter } from "./routes/policies.js";
import { actionsRouter } from "./routes/actions.js";
import { approvalsRouter } from "./routes/approvals.js";
import { auditRouter } from "./routes/audit.js";
import { usersRouter } from "./routes/users.js";
import { initEscalationService } from "./lib/escalation.js";

export { initEscalationService };

export const app = express();
app.use(cors({ origin: env.rpOrigin, credentials: true }));
app.use(express.json());
app.use(cookieParser());

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

// Whether a client build is sitting next to this file — true for the
// combined Render deploy image, false for local dev and for the
// docker-compose setup where nginx serves the client as its own container.
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const clientDistPath = process.env.CLIENT_DIST_PATH ?? path.join(__dirname, "../client-dist");
const clientDistExists = fs.existsSync(clientDistPath);
console.log(`[static] __dirname=${__dirname} clientDistPath=${clientDistPath} exists=${clientDistExists}`);
if (!clientDistExists) {
  try {
    console.log(`[static] contents of ${path.dirname(clientDistPath)}:`, fs.readdirSync(path.dirname(clientDistPath)));
  } catch (err) {
    console.log(`[static] could not list ${path.dirname(clientDistPath)}:`, err);
  }
}

const apiRouter = express.Router();
apiRouter.use("/auth", authRouter);
apiRouter.use("/policies", policiesRouter);
apiRouter.use("/actions", actionsRouter);
apiRouter.use("/approvals", approvalsRouter);
apiRouter.use("/audit", auditRouter);
apiRouter.use("/users", usersRouter);
// Bare mount is only for docker-compose's server container, where nginx has
// already stripped the /api prefix before proxying here — a client isn't
// served from this same process, so there's no risk of an API resource name
// (e.g. /policies) shadowing a same-named client-side route. When this
// process IS also serving the client (the combined deploy), skip the bare
// mount entirely: without it, /policies and /approvals could never reach the
// SPA's catch-all below, since Express would resolve the API route first.
if (!clientDistExists) {
  app.use(apiRouter);
}
app.use("/api", apiRouter);

if (clientDistExists) {
  app.use(express.static(clientDistPath));
  app.get("*", (req, res, next) => {
    if (req.path.startsWith("/api") || req.path === "/health" || req.path.startsWith("/socket.io")) {
      next();
      return;
    }
    res.sendFile(path.join(clientDistPath, "index.html"));
  });
}

// Last-resort safety net: any error a route didn't explicitly handle (now
// including ones thrown/rejected inside an async handler, forwarded here by
// express-async-errors above) ends this one request with a generic 500
// instead of crashing the process and taking down every other in-flight
// request too. Must be registered after every other app.use/route -- Express
// only recognizes a 4-argument function as error-handling middleware, and
// only errors passed to routes registered *before* this point ever reach it.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: unknown, req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error("[unhandled route error]", err);
  if (res.headersSent) return;
  res.status(500).json({ error: "Internal server error" });
});

export const httpServer = http.createServer(app);

// Used for the second-device push-approve flow: a login attempt on device A
// opens a room keyed by a short-lived challenge id; device B joins after
// scanning/tapping and emits an approve/deny event back into that room.
// Approval votes reuse the same room-per-request-id pattern.
export const io = new SocketIOServer(httpServer, {
  cors: { origin: env.rpOrigin, credentials: true },
});

io.on("connection", (socket) => {
  socket.on("join-challenge", (challengeId: string) => {
    socket.join(challengeId);
  });
});
