# NovaForge — Identity & Governance Platform

[![CI](https://github.com/AryanRajguru22/NovaForge/actions/workflows/ci.yml/badge.svg)](https://github.com/AryanRajguru22/NovaForge/actions/workflows/ci.yml)

NovaForge is a passwordless identity service with a quorum-based approval engine. People sign in
with **passkeys**; sensitive actions are held until the required number of eligible approvers have each
**signed their decision with their own passkey**; and every state change is recorded in a
**hash-chained, trigger-protected audit log**. It also acts as an **OpenID Connect provider** so other
applications can use NovaForge for sign-in and per-application roles.

Built for the Tally CodeBrewers 2026 hackathon by Aryan Rajguru, Rohit Kumar Yadav and Vinayak Tyagi.

> **Status: a rigorously tested reference implementation, not a production service.** See
> [Docs/SECURITY.md](Docs/SECURITY.md) for exactly what is and is not guaranteed.

## What it does

| Area | Capability |
|---|---|
| **Authentication** | WebAuthn passkeys (user verification required) as the primary factor; TOTP and one-time recovery codes as throttled, individually switchable fallbacks. No passwords exist. |
| **Account creation** | Invitation / enrollment links (single-use, 24 h). First administrator via `npm run bootstrap:admin`. Open registration is off by default. |
| **Sessions** | 15-minute access token + rotating 30-day refresh token; replay of a rotated token revokes the whole session; revocation takes effect on the very next request. |
| **Session trust** | A score that decays 5 points/hour since the last server check-in (a *time-since-verification* signal — no device or location intelligence). Sensitive writes need ≥ 50. |
| **Authorization** | Roles `SUPER_ADMIN > ADMIN > SENIOR_APPROVER > APPROVER > MEMBER`, always re-read from the database. Governance changes also require a fresh passkey step-up. |
| **Approval policies** | `N_OF_M`, `ROLE_BASED` and `WEIGHTED` quorum, eligible roles, escalation timeout and a fallback chain. Policies are **snapshotted per request**, so edits never change an in-flight decision. |
| **Approvals** | Server-computed quorum; one vote per approver (DB-enforced); each vote is a WebAuthn signature over the exact decision; concurrency-safe resolution; separation of duties; escalation and fail-closed expiry. |
| **Audit** | Append-only SHA-256 hash chain written in the same transaction as the change; verification endpoint detects modification, deletion, reordering and forks. |
| **Real time** | Socket.io, cookie-authenticated, per-request rooms authorised server-side, revoked sessions disconnected. |
| **OIDC provider** | Authorization code + PKCE (S256, mandatory), ES256 tokens, JWKS, refresh rotation with reuse detection, introspection, revocation, per-application RBAC. |

## Architecture at a glance

```
React SPA ── /api + /socket.io ──▶ Express API ──▶ PostgreSQL 16 (constraints + triggers)
 (Vite, Tailwind)                  (TypeScript, Prisma, zod, Socket.io)
```

* `server/` — API, Prisma schema + migrations, CLI, tests (Vitest against a real PostgreSQL).
* `client/` — SPA (React 18, TypeScript, Vite, Tailwind) with ESLint and Vitest.
* `Docs/ARCHITECTURE.md` — data model, every auth/approval/audit/real-time flow and its tests.
* `Docs/SECURITY.md` — threat model, trust assumptions, findings ledger, limitations.

## Quick start (local development)

Prerequisites: Node 20+, Docker (for PostgreSQL).

```bash
# 1. Database (PostgreSQL 16 on localhost:5432)
docker compose up -d postgres

# 2. Server
cd server
cp .env.example .env          # placeholder secrets are fine for local development
npm install
npx prisma migrate deploy     # applies all migrations
npm run dev                   # http://localhost:4000

# 3. Create the first administrator (prints a single-use passkey enrollment link)
npx tsx src/cli/bootstrap-admin.ts --email you@example.com --name "Your Name"

# 4. Client (new terminal)
cd client
npm install
npm run dev                   # http://localhost:5173 — proxies /api to the server
```

Open the enrollment link the CLI printed (`/login?enroll=…`), create a passkey, then sign in.
The bootstrap command refuses to run once an active SUPER_ADMIN exists. Passkeys need `localhost` or
HTTPS and an authenticator (platform biometrics, a security key, or a browser/OS passkey provider).

### Full stack in Docker (demo)

```bash
cp server/.env.example server/.env
docker compose up --build              # http://localhost:8080
docker compose exec server node dist/cli/bootstrap-admin.js --email you@example.com --name "Your Name"
```

This is a **local demo over plain HTTP** and runs the server with `NODE_ENV=development` on purpose
(production mode refuses placeholder secrets). Ports are configurable (`POSTGRES_PORT`,
`SERVER_PORT`, `CLIENT_PORT`) and a second isolated copy can be run with `docker compose -p <name> …`.

## Configuration

All server variables (see `server/.env.example`):

| Variable | Required | Purpose |
|---|---|---|
| `DATABASE_URL` | yes | PostgreSQL connection string. |
| `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET` | yes | Session token signing (must differ). Generate: `openssl rand -base64 48`. |
| `TOTP_ENCRYPTION_KEY` | yes | Encrypts TOTP secrets at rest. |
| `RP_ID`, `RP_NAME`, `RP_ORIGIN` | yes | WebAuthn relying party; must match the browser origin exactly. |
| `PORT` | no | Default 4000. |
| `TRUST_PROXY` | behind a proxy | Number of reverse proxies in front (e.g. `1`). Leave unset when directly exposed. |
| `ALLOW_OPEN_REGISTRATION` | no | `true` lets anyone self-register (off by default). |
| `IDENTITY_ISSUER`, `IDENTITY_SIGNING_KEY_ID`, `IDENTITY_SIGNING_PRIVATE_KEY` | **production** | OIDC/identity-assertion signing (ES256, PKCS#8 PEM). In development a key is generated into `server/.dev/`. |
| `IDENTITY_PREVIOUS_PUBLIC_KEYS` | no | JSON array of retired public JWKs still accepted during rotation. |
| `NODE_ENV=production` | — | Enables fail-fast checks: secrets ≥ 32 chars, not placeholders, access ≠ refresh, `IDENTITY_*` present. |

## Testing

Server tests run against a **real PostgreSQL**. They create users, sessions, policies and audit rows
in whatever database `DATABASE_URL` points to, so **use a throwaway database, never one with data you
care about**:

```bash
docker run -d --name nf-test-pg -e POSTGRES_USER=nf -e POSTGRES_PASSWORD=nf -e POSTGRES_DB=nf \
  -p 127.0.0.1:55432:5432 postgres:16-alpine

cd server
export DATABASE_URL=postgresql://nf:nf@localhost:55432/nf
npx prisma migrate deploy
npm test                       # full suite (~4 min)
npx vitest run test/hardening.test.ts   # a single file
npx tsc -p tsconfig.json --noEmit       # typecheck

cd ../client
npm run lint && npm test && npm run build
```

What the suites cover (all with real WebAuthn verification via a software authenticator, no mocks of
the database): authentication and fallback abuse, refresh rotation/replay/concurrency, session trust,
RBAC, approval quorum (all three types), concurrent votes and expiry races, signed-vote binding and
replay, policy snapshots and cycles, step-up, audit tampering (payload/hash/gap/reorder/fork), Socket.io
isolation and revocation, OIDC/PKCE/replay, service identities, DB triggers, and boot configuration.

The `pashupatastra-e2e` test drives a real second application against NovaForge and **self-skips**
unless the sibling Pashupatastra repository is present (`PASHUPATASTRA_DIR`); CI therefore does not run it.

CI (`.github/workflows/ci.yml`): Prisma validate → migrate on an empty DB → drift check → typecheck →
build → server tests (PostgreSQL 16 service) → `npm audit` (prod, fail on high); client lint → tests →
build → audit; Docker builds of all three images. Workflow permissions are `contents: read`.

## Deployment

* **Combined single-origin image** (`Dockerfile.render`): the API serves the built SPA. This is what the
  Render configuration (`render.yaml`) targets: build, push, create a web service from the image, and set
  `DATABASE_URL`, the three secrets, `TRUST_PROXY=1`, and the `IDENTITY_*` variables. `RP_ID`/`RP_ORIGIN`
  are derived from Render's `RENDER_EXTERNAL_URL`. The container runs `prisma migrate deploy` on start,
  as a non-root user, with a health check on `/ready`.
* **First administrator on a fresh deployment:**
  `node dist/cli/bootstrap-admin.js --email admin@example.com --name "Admin"` inside the container.
* Health endpoints: `/health` (liveness) and `/ready` (database reachable). The process shuts down
  gracefully on SIGTERM.
* **Run exactly one instance.** Challenge and burst-limit state is in memory (see Known limitations).

## Operator tools

| Command | Purpose |
|---|---|
| `npm run bootstrap:admin -- --email … --name …` | Create the first SUPER_ADMIN (compiled; works in the production image). |
| `npx tsx scripts/create-enrollment-token.ts --email …` | Issue a passkey enrollment link for an existing account (recovery). Needs a source checkout. |
| `npx tsx scripts/iam.ts register-pashupatastra …` / `assign …` | Register an OIDC application / assign an application role (break-glass; the API is `/api/applications`). |

## Known limitations

NovaForge records and proves approval decisions; it does **not** execute the approved action or notify
a relying service. It has no organisation/tenant model, no automated audit-anchor export, no database
role separation, no KMS/HSM, no notifications, no monitoring, and is single-instance. The audit chain is
tamper-*evident*, not tamper-proof against a privileged database operator. There is no web UI for
managing OIDC applications yet (API and CLI only). The full list, with rationale, is in
[Docs/SECURITY.md](Docs/SECURITY.md#6-known-limitations-complete-list-of-things-the-product-does-not-do).

## References

`REFERENCES.md` lists the standards and libraries this builds on. The repository does not yet declare a license.
