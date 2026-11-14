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
import { internalRouter } from "./routes/internal.js";
import { serviceAccountsRouter } from "./routes/serviceAccounts.js";
import { applicationsRouter } from "./routes/applications.js";
import { oauthRouter, serveDiscovery, v1Router } from "./routes/oauth.js";
import { securityHeaders } from "./middleware/securityHeaders.js";
import { prisma } from "./lib/prisma.js";
import { requestContextMiddleware } from "./lib/requestContext.js";
import { getPublicJwks, IdentityKeysUnavailableError } from "./lib/identityKeys.js";
import { initEscalationService } from "./lib/escalation.js";
import { initSocketSecurity, stopSocketSecurity } from "./lib/socketSecurity.js";

export { initEscalationService, initSocketSecurity, stopSocketSecurity };

export const app = express();
// Behind a reverse proxy (nginx, Render's edge) req.ip is the proxy's address
// unless Express is told how many proxy hops to trust. Without this, every
// client shares one IP for rate limiting. Set TRUST_PROXY to the hop count
// (e.g. "1") or an Express trust-proxy value for the actual deployment; it is
// deliberately not enabled by default, since trusting X-Forwarded-For from a
// directly exposed server would let clients choose their own IP.
if (process.env.TRUST_PROXY) {
  const value = process.env.TRUST_PROXY;
  app.set("trust proxy", /^\d+$/.test(value) ? Number(value) : value === "true" ? true : value);
}
app.disable("x-powered-by");
app.use(requestContextMiddleware);
app.use(securityHeaders);
// Discovery, JWKS and the token/userinfo endpoints are called by other origins
// with no cookies, so they get open (credential-less) CORS. Everything else is
// the NovaForge SPA's API and only answers its own origin, with credentials.
const openCors = cors({ origin: "*", credentials: false, methods: ["GET", "POST", "OPTIONS"], allowedHeaders: ["Authorization", "Content-Type"] });
const appCors = cors({ origin: env.rpOrigin, credentials: true });
const OPEN_CORS_PATH = /^(\/api)?(\/\.well-known\/|\/oauth\/(token|userinfo)$)/;
app.use((req, res, next) => (OPEN_CORS_PATH.test(req.path) ? openCors(req, res, next) : appCors(req, res, next)));
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));
app.use(cookieParser());

// Liveness: the process is up. Readiness: it can actually serve (database
// reachable). Neither reveals configuration.
app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});
app.get(["/ready", "/api/ready"], async (_req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ status: "ready" });
  } catch {
    res.status(503).json({ status: "unavailable" });
  }
});

// Public verification keys for identity assertions issued to relying
// services. Contains public keys only.
function serveJwks(_req: express.Request, res: express.Response): void {
  try {
    res.setHeader("Cache-Control", "public, max-age=300");
    res.json(getPublicJwks());
  } catch (err) {
    if (err instanceof IdentityKeysUnavailableError) {
      res.status(503).json({ error: "Identity keys are not configured" });
      return;
    }
    throw err;
  }
}
app.get("/.well-known/jwks.json", serveJwks);
app.get("/api/.well-known/jwks.json", serveJwks);
app.get("/.well-known/openid-configuration", serveDiscovery);
app.get("/api/.well-known/openid-configuration", serveDiscovery);

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
apiRouter.use("/service-accounts", serviceAccountsRouter);
apiRouter.use("/applications", applicationsRouter);
apiRouter.use("/oauth", oauthRouter);
apiRouter.use("/v1", v1Router);
apiRouter.use("/internal", internalRouter);
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

// Used for the second-device push-approve flow: an approval request opens a
// room keyed by its own id; a second device joins after scanning/sharing a
// link and receives the same live vote-cast/status-update events the first
// device does. Room joins are authenticated and authorized in
// server/src/lib/socketSecurity.ts (initSocketSecurity, called from
// index.ts / test/testServer.ts) -- this module only constructs the server;
// it deliberately registers no connection handling of its own.
export const io = new SocketIOServer(httpServer, {
  cors: { origin: env.rpOrigin, credentials: true },
});
