# NovaForge

Passwordless-first authentication platform with a configurable M-of-N approval-policy engine.

## Stack

- `server/` — Node.js + TypeScript + Express + Prisma (PostgreSQL), WebAuthn passkeys via
  `@simplewebauthn`, TOTP fallback via `otplib`, Socket.io for the second-device push-approve flow.
- `client/` — React + Vite + TypeScript + Tailwind.

## Local setup

1. Start Postgres: `docker compose up -d`
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

## Testing

Server unit tests run via `npm test` in `server/` (Vitest). Prioritize coverage of the approval
quorum resolution logic, since it is the most correctness-sensitive part of the system.
