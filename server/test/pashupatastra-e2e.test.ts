import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  startTestServer,
  stopTestServer,
  apiRequest,
  createUserWithToken,
  addMockPasskey,
  authenticatorFor,
  governanceProof,
  cleanupUsers,
  runSuffix,
} from "./testServer.js";
import { prisma } from "../src/lib/prisma.js";
import { resetRateLimitBuckets } from "../src/middleware/rateLimit.js";
import { assignRoleByEmail, ensureApplication, pashupatastraSpec } from "../src/lib/oauth/provision.js";

// Cross-application end-to-end test: the REAL NovaForge server (in-process) and
// the REAL Pashupatastra backend (a uvicorn child process), talking over HTTP.
// The test plays the browser: it follows redirects by hand and keeps one cookie
// jar per site. Users sign in to NovaForge with a real WebAuthn ceremony (a
// software authenticator, verified by the unmodified library).
//
// Needs the Pashupatastra repository next to this one (or PASHUPATASTRA_DIR) and
// its Python dependencies; skipped otherwise.

const PP_DIR = process.env.PASHUPATASTRA_DIR ?? path.resolve(process.cwd(), "../../Pashupatastra");
const PYTHON = process.env.PYTHON ?? "python";
const FRONTEND = "http://localhost:3000";
const available = existsSync(path.join(PP_DIR, "backend", "app", "api", "main.py"));

class Jar {
  private cookies = new Map<string, string>();
  absorb(res: Response): void {
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const idx = pair.indexOf("=");
      const name = pair.slice(0, idx).trim();
      const value = pair.slice(idx + 1).trim();
      if (/max-age=0/i.test(line) || /expires=thu, 01 jan 1970/i.test(line) || value === "") this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
  }
  header(): string {
    return [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ");
  }
  get(name: string): string | undefined {
    return this.cookies.get(name);
  }
  clear(): void {
    this.cookies.clear();
  }
}

async function http(jar: Jar, url: string, init: RequestInit & { headers?: Record<string, string> } = {}): Promise<Response> {
  const cookie = jar.header();
  const res = await fetch(url, { redirect: "manual", ...init, headers: { ...(cookie ? { Cookie: cookie } : {}), ...(init.headers ?? {}) } });
  jar.absorb(res);
  return res;
}

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address() as { port: number };
      srv.close(() => resolve(port));
    });
    srv.on("error", reject);
  });
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe.skipIf(!available)("Pashupatastra x NovaForge, end to end", () => {
  let nf = "";
  let pp = "";
  let child: ChildProcess | null = null;
  let ppLog = "";
  let tmp = "";
  let appId = "";
  let secret = "";
  let ppEnv: Record<string, string> = {};

  const emails = {
    root: `e2e-root-${runSuffix}@example.com`,
    alice: `e2e-alice-${runSuffix}@example.com`,
    bob: `e2e-bob-${runSuffix}@example.com`,
    carol: `e2e-carol-${runSuffix}@example.com`,
    dave: `e2e-dave-${runSuffix}@example.com`,
    erin: `e2e-erin-${runSuffix}@example.com`,
  };
  const people: Record<string, { id: string; token: string }> = {};
  let root: { id: string; token: string };

  async function startPashupatastra(): Promise<void> {
    child = spawn(PYTHON, ["-m", "uvicorn", "backend.app.api.main:app", "--host", "127.0.0.1", "--port", String(new URL(pp).port)], {
      cwd: PP_DIR,
      env: { ...process.env, ...ppEnv },
      stdio: ["ignore", "pipe", "pipe"],
    });
    child.stdout?.on("data", (d) => (ppLog += d));
    child.stderr?.on("data", (d) => (ppLog += d));
    for (let i = 0; i < 120; i++) {
      try {
        const res = await fetch(`${pp}/auth/config`);
        if (res.ok) return;
      } catch {
        /* not up yet */
      }
      if (child.exitCode !== null) throw new Error(`Pashupatastra exited early:\n${ppLog}`);
      await sleep(500);
    }
    throw new Error(`Pashupatastra did not start:\n${ppLog}`);
  }

  async function stopPashupatastra(): Promise<void> {
    if (!child) return;
    const proc = child;
    child = null;
    await new Promise<void>((resolve) => {
      proc.once("exit", () => resolve());
      proc.kill();
      setTimeout(() => resolve(), 5000);
    });
  }

  /** WebAuthn sign-in at NovaForge; returns a cookie jar holding its session. */
  async function signInToNovaForge(email: string, userId: string): Promise<Jar> {
    resetRateLimitBuckets(); // every sign-in comes from 127.0.0.1; NovaForge's per-email burst limit is not under test here
    const jar = new Jar();
    const options = await (await http(jar, `${nf}/api/auth/login/options`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email }) })).json();
    const response = authenticatorFor(userId).createAssertion(options.challenge);
    const verified = await http(jar, `${nf}/api/auth/login/verify`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, response }) });
    expect(verified.status, await verified.clone().text()).toBe(200);
    expect(jar.get("accessToken")).toBeTruthy();
    return jar;
  }

  /** The Pashupatastra callback URL the browser was sent to, mapped onto the test port. */
  const toPp = (location: string) => location.replace(`${FRONTEND}/api/pp`, pp);

  /** Drives the whole redirect dance. Returns Pashupatastra's cookie jar and where the browser landed. */
  async function loginToPashupatastra(nfJar: Jar, ppJar: Jar, returnTo = "/jobs") {
    const start = await http(ppJar, `${pp}/auth/login?return_to=${encodeURIComponent(returnTo)}`);
    expect(start.status).toBe(302);
    const authorizeUrl = start.headers.get("location")!;
    expect(authorizeUrl.startsWith(`${nf}/api/oauth/authorize?`)).toBe(true);
    const authorized = await http(nfJar, authorizeUrl);
    expect(authorized.status).toBe(302);
    const back = authorized.headers.get("location")!;
    if (!back.startsWith(`${FRONTEND}/api/pp/auth/callback`)) return { landed: back, ppJar };
    const done = await http(ppJar, toPp(back));
    expect(done.status).toBe(302);
    return { landed: done.headers.get("location")!, ppJar };
  }

  const csrf = { "X-PP-CSRF": "1", Origin: FRONTEND, "Content-Type": "application/json" };
  const job = { track_id: "UP-1", job_type: "BALLAST_TAMPING", distance_start: 1000, distance_end: 1400, workers_min: 2, workers_max: 4, description: "E2E defect" };

  const ppGet = (jar: Jar, p: string) => http(jar, `${pp}${p}`);
  const ppPost = (jar: Jar, p: string, body: unknown = {}) => http(jar, `${pp}${p}`, { method: "POST", headers: csrf, body: JSON.stringify(body) });

  async function adminAssign(roleKey: string, userId: string, resource = "*") {
    const roles = (await apiRequest(`/applications/${appId}`, { token: root.token })).data.roles as { id: string; key: string }[];
    return apiRequest(`/applications/${appId}/assignments`, {
      method: "POST",
      token: root.token,
      body: { userId, roleId: roles.find((r) => r.key === roleKey)!.id, resource, response: await governanceProof(root, "app") },
    });
  }

  async function adminUnassign(userId: string) {
    const list = await apiRequest(`/applications/${appId}/assignments?pageSize=100`, { token: root.token });
    for (const item of list.data.items.filter((i: { user: { id: string } }) => i.user.id === userId)) {
      const res = await apiRequest(`/applications/${appId}/assignments/${item.id}`, { method: "DELETE", token: root.token, body: { response: await governanceProof(root, "app") } });
      expect(res.status).toBe(200);
    }
  }

  beforeAll(async () => {
    nf = await startTestServer();
    process.env.IDENTITY_ISSUER = nf;
    tmp = mkdtempSync(path.join(tmpdir(), "pp-e2e-"));

    const r = await createUserWithToken({ email: emails.root, role: "SUPER_ADMIN", name: "Root" });
    root = { id: r.user.id, token: r.token };
    await addMockPasskey(root.id);
    for (const key of ["alice", "bob", "carol", "dave", "erin"] as const) {
      const u = await createUserWithToken({ email: emails[key], name: `${key[0].toUpperCase()}${key.slice(1)} Example` });
      await addMockPasskey(u.user.id);
      people[key] = { id: u.user.id, token: u.token };
    }

    // Provision the application exactly as an operator would.
    const provisioned = await ensureApplication(pashupatastraSpec(FRONTEND), { issueSecretIfNone: true });
    appId = provisioned.applicationId;
    secret = provisioned.secret!;
    await assignRoleByEmail({ clientId: "pashupatastra", email: emails.alice, roleKey: "worker" });
    await assignRoleByEmail({ clientId: "pashupatastra", email: emails.bob, roleKey: "authority" });
    await assignRoleByEmail({ clientId: "pashupatastra", email: emails.dave, roleKey: "worker" });
    await assignRoleByEmail({ clientId: "pashupatastra", email: emails.erin, roleKey: "engineer" });
    // short-lived access tokens so the refresh path is exercised for real
    await prisma.oAuthClient.update({ where: { id: appId }, data: { accessTokenTtlSec: 3 } });

    const port = await freePort();
    pp = `http://127.0.0.1:${port}`;
    ppEnv = {
      PASHUPAT_AUTH_MODE: "novaforge",
      PASHUPAT_AUTH_ISSUER: nf,
      PASHUPAT_AUTH_CLIENT_ID: "pashupatastra",
      PASHUPAT_AUTH_CLIENT_SECRET: secret,
      PASHUPAT_AUTH_AUDIENCE: "pashupatastra-api",
      PASHUPAT_AUTH_REDIRECT_URI: `${FRONTEND}/api/pp/auth/callback`,
      PASHUPAT_AUTH_FRONTEND_ORIGIN: FRONTEND,
      PASHUPAT_AUTH_JOBS_DB: path.join(tmp, "enforced.db"),
      PASHUPAT_AUTH_FRESHNESS_SECONDS: "1",
      PASHUPAT_JOBS_DB: path.join(tmp, "unused-demo.db"),
    };
    await startPashupatastra();
  }, 120_000);

  afterAll(async () => {
    if (process.env.E2E_DEBUG) console.log(ppLog.slice(-4000));
    await stopPashupatastra();
    await prisma.oAuthClient.deleteMany({ where: { id: appId } });
    await cleanupUsers(Object.values(emails));
    await stopTestServer();
  });

  it("serves nothing without a session, and refuses declared identities", async () => {
    const anon = new Jar();
    expect((await ppGet(anon, "/v1/jobs")).status).toBe(401);
    expect((await ppGet(anon, "/auth/me")).status).toBe(401);
    const declared = await http(anon, `${pp}/v1/jobs`, { headers: { "X-Actor-Id": "AUTHORITY-017", "X-Actor-Role": "AUTHORITY" } });
    expect(declared.status).toBe(400);
    expect((await ppPost(anon, "/optimize", {})).status).toBe(401);
    expect(((await (await fetch(`${pp}/auth/config`)).json()) as { mode: string }).mode).toBe("novaforge");
  });

  it("redirects an unauthenticated browser to NovaForge's sign-in, then completes the flow after login", async () => {
    const nfJar = new Jar();
    const ppJar = new Jar();
    // No NovaForge session yet: authorize bounces to NovaForge's own sign-in page.
    const start = await http(ppJar, `${pp}/auth/login?return_to=/review`);
    const bounce = await http(nfJar, start.headers.get("location")!);
    expect(bounce.status).toBe(302);
    const signin = new URL(bounce.headers.get("location")!);
    expect(signin.pathname).toBe("/oauth/signin");
    expect(signin.searchParams.get("client_id")).toBe("pashupatastra");

    // The user signs in with their passkey, and the very same request is resumed.
    const nfSession = await signInToNovaForge(emails.alice, people.alice.id);
    const resumed = await http(nfSession, `${nf}/api/oauth/authorize?${signin.searchParams.toString()}`);
    const callback = resumed.headers.get("location")!;
    expect(callback.startsWith(`${FRONTEND}/api/pp/auth/callback?code=`)).toBe(true);
    expect(new URL(callback).searchParams.get("iss")).toBe(nf);
    const done = await http(ppJar, toPp(callback));
    expect(done.headers.get("location")).toBe(`${FRONTEND}/review`);
    expect(ppJar.get("pp_session")).toBeTruthy();

    const me = await (await ppGet(ppJar, "/auth/me")).json();
    expect(me).toMatchObject({ authenticated: true, active_role: "WORKER", name: "Alice Example" });
    expect(me.permissions).toContain("job.report_job");
    expect(JSON.stringify(me)).not.toContain(people.alice.id);
  });

  it("lets a permitted user do permitted things and denies the rest", async () => {
    const aliceNf = await signInToNovaForge(emails.alice, people.alice.id);
    const { ppJar: alice } = await loginToPashupatastra(aliceNf, new Jar());
    const created = await ppPost(alice, "/v1/jobs", job);
    expect(created.status, await created.clone().text()).toBe(201);
    const { job_id } = await created.json();
    const history = await (await ppGet(alice, `/v1/jobs/${job_id}/history`)).json();
    expect(history.events[0].actor).toMatchObject({ role: "WORKER", assurance: "AUTHENTICATED" });

    // a worker cannot approve a proposal or request an optimization
    expect((await ppPost(alice, `/v1/jobs/${job_id}/proposal/approve`, { expected_proposal_run_id: "x" })).status).toBe(403);
    expect((await ppPost(alice, "/v1/corridors/CORRIDOR_A/optimize-jobs")).status).toBe(403);
    expect((await ppPost(alice, "/optimize", {})).status).toBe(403);

    // an authority can read it but not report one
    const bobNf = await signInToNovaForge(emails.bob, people.bob.id);
    const { ppJar: bob } = await loginToPashupatastra(bobNf, new Jar());
    expect((await ppGet(bob, `/v1/jobs/${job_id}`)).status).toBe(200);
    expect((await ppPost(bob, "/v1/jobs", job)).status).toBe(403);

    // a user with no role in the application is refused at NovaForge, and no session results
    const carolNf = await signInToNovaForge(emails.carol, people.carol.id);
    const carolPp = new Jar();
    const attempt = await loginToPashupatastra(carolNf, carolPp);
    expect(new URL(attempt.landed).searchParams.get("error") ?? attempt.landed).toContain("not_authorized");
    expect((await ppGet(carolPp, "/auth/me")).status).toBe(401);
  });

  it("enforces an administrator's role change and permission change within the staleness bound", async () => {
    // Role change: dave (worker) is moved to authority.
    const daveNf = await signInToNovaForge(emails.dave, people.dave.id);
    const { ppJar: dave } = await loginToPashupatastra(daveNf, new Jar());
    expect((await ppPost(dave, "/v1/jobs", job)).status).toBe(201);
    expect((await adminAssign("authority", people.dave.id)).status).toBe(201);
    await adminUnassign(people.dave.id).catch(() => undefined); // removes both; re-add below
    expect((await adminAssign("authority", people.dave.id)).status).toBe(201);
    await sleep(1300);
    const afterChange = await ppPost(dave, "/v1/jobs", job);
    expect([401, 403]).toContain(afterChange.status); // no longer a worker
    // signing in again yields the new role
    const daveNf2 = await signInToNovaForge(emails.dave, people.dave.id);
    const { ppJar: dave2 } = await loginToPashupatastra(daveNf2, new Jar());
    expect((await (await ppGet(dave2, "/auth/me")).json()).active_role).toBe("AUTHORITY");
    expect((await ppPost(dave2, "/v1/jobs", job)).status).toBe(403);

    // Permission change: take job.report_job away from the worker role itself.
    const aliceNf = await signInToNovaForge(emails.alice, people.alice.id);
    const { ppJar: alice } = await loginToPashupatastra(aliceNf, new Jar());
    expect((await ppPost(alice, "/v1/jobs", job)).status).toBe(201);
    const detail = (await apiRequest(`/applications/${appId}`, { token: root.token })).data;
    const worker = detail.roles.find((r: { key: string }) => r.key === "worker");
    const without = worker.permissions.filter((p: string) => p !== "job.report_job");
    expect((await apiRequest(`/applications/${appId}/roles/${worker.id}`, { method: "PUT", token: root.token, body: { permissions: without } })).status).toBe(200);
    await sleep(1300);
    const denied = await ppPost(alice, "/v1/jobs", job);
    expect(denied.status).toBe(403);
    expect((await denied.json()).code).toBe("AUTHORIZATION_DENIED");
    // ...and restoring it restores access without a new login
    expect((await apiRequest(`/applications/${appId}/roles/${worker.id}`, { method: "PUT", token: root.token, body: { permissions: worker.permissions } })).status).toBe(200);
    await sleep(1300);
    expect((await ppPost(alice, "/v1/jobs", job)).status).toBe(201);
  });

  it("refreshes short-lived access tokens transparently and survives many refresh cycles", async () => {
    const erinNf = await signInToNovaForge(emails.erin, people.erin.id);
    const { ppJar: erin } = await loginToPashupatastra(erinNf, new Jar());
    for (let i = 0; i < 3; i++) {
      await sleep(3300); // access token lifetime is 3 s: every pass needs a rotation
      const res = await ppGet(erin, "/v1/jobs");
      expect(res.status, await res.clone().text()).toBe(200);
    }
    const grants = await prisma.oAuthRefreshToken.count({ where: { grant: { userId: people.erin.id } } });
    expect(grants).toBeGreaterThanOrEqual(3);
    expect(await prisma.oAuthRefreshToken.count({ where: { grant: { userId: people.erin.id }, usedAt: { not: null } } })).toBeGreaterThanOrEqual(2);
  }, 30_000);

  it("stops serving a revoked session, a revoked grant and a suspended user", async () => {
    // 1. NovaForge session revoked from another device (DELETE /auth/sessions/:id)
    const nfJar1 = await signInToNovaForge(emails.alice, people.alice.id);
    const { ppJar: p1 } = await loginToPashupatastra(nfJar1, new Jar());
    expect((await ppGet(p1, "/v1/jobs")).status).toBe(200);
    const sessions = await apiRequest("/auth/sessions", { token: nfJar1.get("accessToken") });
    const current = sessions.data.find((s: { current?: boolean }) => s.current) ?? sessions.data[0];
    await prisma.session.delete({ where: { id: current.id } });
    await sleep(1300);
    expect((await ppGet(p1, "/v1/jobs")).status).toBe(401);

    // 2. an administrator revokes the application's grant
    const nfJar2 = await signInToNovaForge(emails.bob, people.bob.id);
    const { ppJar: p2 } = await loginToPashupatastra(nfJar2, new Jar());
    expect((await ppGet(p2, "/v1/jobs")).status).toBe(200);
    const grant = await prisma.oAuthGrant.findFirstOrThrow({ where: { userId: people.bob.id, revokedAt: null }, orderBy: { createdAt: "desc" } });
    expect((await apiRequest(`/applications/${appId}/grants/${grant.id}`, { method: "DELETE", token: root.token })).status).toBe(200);
    await sleep(1300);
    expect((await ppGet(p2, "/v1/jobs")).status).toBe(401);
    expect((await ppGet(p2, "/v1/jobs")).status).toBe(401); // and it stays ended

    // 3. the account is suspended
    const nfJar3 = await signInToNovaForge(emails.dave, people.dave.id);
    const { ppJar: p3 } = await loginToPashupatastra(nfJar3, new Jar());
    expect((await ppGet(p3, "/v1/jobs")).status).toBe(200);
    await prisma.user.update({ where: { id: people.dave.id }, data: { status: "SUSPENDED" } });
    await sleep(1300);
    expect((await ppGet(p3, "/v1/jobs")).status).toBe(401);
    await prisma.user.update({ where: { id: people.dave.id }, data: { status: "ACTIVE" } });
  }, 30_000);

  it("logs out of both applications, and a copied session cookie is worthless afterwards", async () => {
    const nfJar = await signInToNovaForge(emails.alice, people.alice.id);
    const { ppJar } = await loginToPashupatastra(nfJar, new Jar());
    const copied = ppJar.header();
    const out = await ppPost(ppJar, "/auth/logout");
    expect(out.status).toBe(200);
    const logoutUrl = (await out.json()).logout_url as string;
    expect(logoutUrl.startsWith(`${nf}/api/oauth/logout?`)).toBe(true);
    // The browser follows it to NovaForge, which ends its session and sends the user back.
    const bye = await http(nfJar, logoutUrl);
    expect(bye.status).toBe(302);
    expect(bye.headers.get("location")!.startsWith(`${FRONTEND}/`)).toBe(true);
    expect(nfJar.get("accessToken")).toBeUndefined();
    expect((await ppGet(ppJar, "/v1/jobs")).status).toBe(401);
    expect((await http(new Jar(), `${pp}/v1/jobs`, { headers: { Cookie: copied } })).status).toBe(401);
    // and NovaForge no longer authorizes silently
    const again = await http(nfJar, (await http(new Jar(), `${pp}/auth/login`)).headers.get("location")!);
    expect(new URL(again.headers.get("location")!).pathname).toBe("/oauth/signin");
  });

  it("keeps working after Pashupatastra restarts: sessions end, single sign-on makes login seamless", async () => {
    const nfJar = await signInToNovaForge(emails.alice, people.alice.id);
    const { ppJar: before } = await loginToPashupatastra(nfJar, new Jar());
    expect((await ppGet(before, "/v1/jobs")).status).toBe(200);
    await stopPashupatastra();
    await startPashupatastra();
    // the in-memory session is gone (by design)...
    expect((await ppGet(before, "/v1/jobs")).status).toBe(401);
    // ...but the NovaForge session is intact, so signing in again needs no prompt
    const { ppJar: after, landed } = await loginToPashupatastra(nfJar, new Jar());
    expect(landed).toBe(`${FRONTEND}/jobs`);
    expect((await ppGet(after, "/v1/jobs")).status).toBe(200);
    // data written before the restart is still there
    const list = await (await ppGet(after, "/v1/jobs")).json();
    expect(list.items.length).toBeGreaterThan(0);
  }, 60_000);

  it("rejects tampered callbacks end to end (state, code reuse)", async () => {
    const nfJar = await signInToNovaForge(emails.alice, people.alice.id);
    const ppJar = new Jar();
    const start = await http(ppJar, `${pp}/auth/login`);
    const authorized = await http(nfJar, start.headers.get("location")!);
    const back = toPp(authorized.headers.get("location")!);
    const bad = await http(ppJar, back.replace(/state=[^&]+/, "state=forged"));
    expect(bad.headers.get("location")).toContain("auth/error?code=");
    // the (consumed) transaction cannot be replayed even with the right state
    const replay = await http(ppJar, back);
    expect(replay.headers.get("location")).toContain("login_expired");
    expect((await ppGet(ppJar, "/auth/me")).status).toBe(401);
  });
});
