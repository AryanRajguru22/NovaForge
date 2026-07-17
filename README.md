# NovaForge

Passwordless-first authentication platform with a configurable M-of-N approval-policy engine.

## Stack

- `server/` — Node.js + TypeScript + Express + Prisma (PostgreSQL), WebAuthn passkeys via
  `@simplewebauthn`, TOTP fallback via `otplib`, Socket.io for the second-device push-approve flow.
- `client/` — React + Vite + TypeScript + Tailwind.

## Local setup

### Option A — hot-reload dev (recommended while actively developing)

1. Start Postgres: `docker compose up -d postgres`
2. Server:
   ```
   cd server
   cp .env.example .env
   npm install
   npm run prisma:migrate
   npm run dev
   ```
3. Client:
   ```
   cd client
   npm install
   npm run dev
   ```
4. Client dev server runs on `http://localhost:5173`, server on `http://localhost:4000`
   (client proxies `/api/*` to the server — see `client/vite.config.ts`).

### Option B — full stack in Docker (closest to how it'd run for a demo)

1. `cp server/.env.example server/.env` if you haven't already (compose reads the server's
   secrets from this file; only `DATABASE_URL` and `RP_ORIGIN` are overridden for the
   container network).
2. `docker compose up --build`
3. Open `http://localhost:8080` — nginx serves the built client and proxies `/api/*` and
   `/socket.io/*` to the server container. The server runs `prisma migrate deploy`
   automatically on startup, so no manual migration step is needed here.

Both `server/Dockerfile` and `client/Dockerfile` are multi-stage: the final images contain
no devDependencies or source-only tooling (the client's final image is nginx + static
assets only, no Node runtime at all).

## Testing

Server unit tests run via `npm test` in `server/` (Vitest). Prioritize coverage of the approval
quorum resolution logic, since it is the most correctness-sensitive part of the system.
