# NovaForge

Passwordless-first authentication platform with a configurable M-of-N approval-policy engine.
Built for the Tally CodeBrewers hackathon ("Commander of Full Stack" track). This file is setup
+ a feature index; ask a team member for the full narrative writeup of what was built and why.

## Stack

- `server/` — Node.js + TypeScript + Express + Prisma (PostgreSQL), WebAuthn passkeys via
  `@simplewebauthn`, TOTP fallback via `otplib`, Socket.io for the second-device push-approve flow.
- `client/` — React + Vite + TypeScript + Tailwind.

## Features

- **Passwordless login** — WebAuthn passkeys as the primary factor, TOTP and one-time recovery
  codes (scrypt-hashed, shown once) as fallbacks. Regenerating recovery codes requires a fresh
  passkey signature, not just a valid session.
- **Sessions that degrade, not expire** — trust decays 5 points/hour since last check-in rather
  than hard-expiring; the client refreshes proactively (`App.tsx`, every 4 minutes) and reactively
  on any 401, which is also what makes decay/recovery actually happen instead of sitting frozen.
  Sensitive-action writes (creating an action, casting a vote) are gated on trust ≥ 50
  (`server/src/middleware/requireTrust.ts`).
- **Revoking a session is immediate** — every authenticated request re-checks that its session
  still exists in the database, so revoking a device from another one takes effect on that
  device's very next request, not after its access token happens to expire.
- **Approval-policy engine** — N-of-M, role-based, and weighted quorum types, each configurable
  per action type with an escalation timeout and fallback policy. Weighted quorum sums each
  approver's `voteWeight` (per-account, super-admin editable) against the policy's threshold.
- **Non-repudiable votes** — casting a vote requires a fresh WebAuthn signature, and the raw
  assertion is stored on the vote row, so "did you approve this" has a cryptographic answer.
- **Auto-escalation** — approval requests that blow past their deadline reassign to a fallback
  policy or expire (fail-closed) if there isn't one.
- **Tamper-evident audit log** — every meaningful event is hash-chained (`server/src/lib/audit.ts`)
  and viewable at `/audit`, restricted to `SUPER_ADMIN` accounts, with a one-click chain-integrity
  verification.
- **Role-based access** — `SUPER_ADMIN > ADMIN > SENIOR_APPROVER > APPROVER > MEMBER`. A super
  admin is a strict superset of admin (can do everything an admin can, e.g. manage policies) plus
  two things an admin can't: change any user's role or vote weight (`/users`), and view the audit
  log. There's no self-service way to become the first super admin — promote an account by hand:
  ```sql
  UPDATE "User" SET role = 'SUPER_ADMIN' WHERE email = 'you@example.com';
  ```
- **Live updates** — approval requests push vote/escalation/expiry events over Socket.io to every
  device watching them, which is also the backbone of the second-device push-approve flow.

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

## Deployment (Render, via Docker Hub)

The hackathon doesn't require a deployment, but a live instance is kept running anyway. Render's
Blueprint flow (`render.yaml`) needs a connected GitHub repo, which isn't possible for this repo's
org, so it's deployed by hand instead:

1. Build the combined image (client + server in one process, one origin — see
   `Dockerfile.render`'s header comment for why) and push it:
   ```
   docker build -f Dockerfile.render -t twirlyreflex/novaforge:latest .
   docker push twirlyreflex/novaforge:latest
   ```
2. In the Render dashboard: a free Postgres instance named `novaforge-db`, and a Web Service
   using "Existing Image" pointing at `docker.io/twirlyreflex/novaforge:latest`, health check path
   `/health`. Env vars (see `render.yaml` for the authoritative list): `DATABASE_URL` from the
   Postgres instance's connection string, `JWT_ACCESS_SECRET`/`JWT_REFRESH_SECRET` generated,
   `RP_NAME=NovaForge`, `NODE_ENV=production`. `RP_ID`/`RP_ORIGIN` are deliberately left unset —
   `server/src/lib/env.ts` derives both from Render's auto-injected `RENDER_EXTERNAL_URL`, so they
   can never drift from the real assigned `*.onrender.com` URL.
3. The container runs `npx prisma migrate deploy` automatically before starting, so pushing a new
   image with pending migrations is enough — no separate migration step against the Render DB.
4. Redeploy after every push: Render doesn't necessarily re-pull `:latest` on its own, so trigger
   a manual deploy from the dashboard if the live site doesn't reflect a new push.

## Testing

Server tests run via `npm test` in `server/` (Vitest, real Postgres — no mocking the database).
Coverage prioritizes the parts most likely to fail silently: quorum resolution for all three
policy types (`approvals.test.ts`, `weighted-quorum.test.ts`), the audit hash chain
(`audit.test.ts`), trust-level gating (`trust-gating.test.ts`), and session revocation actually
taking effect across devices (`sessions.test.ts`).
