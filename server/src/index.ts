import http from "node:http";
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import { Server as SocketIOServer } from "socket.io";
import { env } from "./lib/env.js";
import { authRouter } from "./routes/auth.js";

const app = express();
app.use(cors({ origin: env.rpOrigin, credentials: true }));
app.use(express.json());
app.use(cookieParser());

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.use("/auth", authRouter);

// Further route modules mount here as they're built, e.g.:
// app.use("/actions", actionsRouter);
// app.use("/approvals", approvalsRouter);
// app.use("/policies", policiesRouter);

const httpServer = http.createServer(app);

// Used for the second-device push-approve flow: a login attempt on device A
// opens a room keyed by a short-lived challenge id; device B joins after
// scanning/tapping and emits an approve/deny event back into that room.
export const io = new SocketIOServer(httpServer, {
  cors: { origin: env.rpOrigin, credentials: true },
});

io.on("connection", (socket) => {
  socket.on("join-challenge", (challengeId: string) => {
    socket.join(challengeId);
  });
});

httpServer.listen(env.port, () => {
  console.log(`NovaForge server listening on :${env.port}`);
});
