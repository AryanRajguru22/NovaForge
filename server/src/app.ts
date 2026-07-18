import http from "node:http";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import { Server as SocketIOServer } from "socket.io";
import { env } from "./lib/env.js";
import { authRouter } from "./routes/auth.js";
import { policiesRouter } from "./routes/policies.js";
import { actionsRouter } from "./routes/actions.js";
import { approvalsRouter } from "./routes/approvals.js";
import { initEscalationService } from "./lib/escalation.js";

export { initEscalationService };

export const app = express();
app.use(cors({ origin: env.rpOrigin, credentials: true }));
app.use(express.json());
app.use(cookieParser());

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

// Mounted twice on purpose: bare (docker-compose's nginx already strips the
// /api prefix before proxying here) and under /api (the combined single-
// service deploy, where this Express app serves the client build directly
// and the browser's same-origin fetches keep their /api prefix all the way
// through — see CLIENT_DIST_PATH below).
const apiRouter = express.Router();
apiRouter.use("/auth", authRouter);
apiRouter.use("/policies", policiesRouter);
apiRouter.use("/actions", actionsRouter);
apiRouter.use("/approvals", approvalsRouter);
app.use(apiRouter);
app.use("/api", apiRouter);

// Serves the built client (and falls back to index.html for client-side
// routes) only when a build is actually present next to this file — true
// for the combined Render deploy image, false for local dev and for the
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
