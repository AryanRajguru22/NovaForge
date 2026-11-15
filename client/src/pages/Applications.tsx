import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ApiError, apiDelete, apiGet, apiPost } from "../lib/api.js";
import { APPLICATION_STEP_UP_PATH, governanceProof } from "../lib/stepUp.js";
import { useAuth } from "../lib/auth.js";

// Console for relying applications that use NovaForge as their OpenID Connect
// provider: who holds which application role, and which sessions an application
// currently holds. Reading is open to ADMIN and SUPER_ADMIN; every change is
// SUPER_ADMIN-only and the server demands a fresh passkey assertion for it.
// Nothing here is a security boundary -- the server enforces all of it. Creating
// applications and defining roles is done through the API or `scripts/iam.ts`.

interface AppSummary {
  id: string;
  clientId: string;
  name: string;
  type: "CONFIDENTIAL" | "PUBLIC";
  status: string;
  _count: { roles: number; permissions: number; assignments: number; grants: number };
}

interface AppDetail extends Omit<AppSummary, "_count"> {
  description: string | null;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  allowedScopes: string[];
  audience: string;
  requireAssignment: boolean;
  accessTokenTtlSec: number;
  secrets: { id: string; label: string | null; createdAt: string; expiresAt: string | null; revokedAt: string | null; lastUsedAt: string | null }[];
  roles: { id: string; key: string; name: string; description: string | null; assignmentCount: number; permissions: string[] }[];
}

interface Assignment {
  id: string;
  user: { id: string; email: string; name: string; status: string };
  role: { id: string; key: string; name: string };
  resource: string;
  expiresAt: string | null;
}

interface Grant {
  id: string;
  user?: { email: string; name: string };
  userId?: string;
  scope: string;
  createdAt: string;
}

interface Page<T> {
  items: T[];
  total: number;
}

interface UserOption {
  id: string;
  email: string;
  name: string;
}

export default function Applications() {
  const navigate = useNavigate();
  const { user: authUser, logout } = useAuth();
  const isSuperAdmin = authUser?.role === "SUPER_ADMIN";
  const [apps, setApps] = useState<AppSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);

  const loadApps = useCallback(async () => {
    try {
      const page = await apiGet<Page<AppSummary>>("/applications?pageSize=100");
      setApps(page.items);
      setError(null);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) navigate("/login", { replace: true });
      else setError(describeError(err));
    } finally {
      setLoading(false);
    }
  }, [navigate]);

  useEffect(() => {
    void loadApps();
  }, [loadApps]);

  async function handleLogout() {
    await logout();
    navigate("/login", { replace: true });
  }

  return (
    <main className="min-h-screen px-6 py-10">
      <div className="mx-auto max-w-5xl space-y-8">
        <nav className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm" aria-label="Primary">
          <Link to="/" className="link-quiet">Home</Link>
          <Link to="/approvals" className="link-quiet">Approvals</Link>
          <Link to="/policies" className="link-quiet">Policies</Link>
          {isSuperAdmin && <Link to="/audit" className="link-quiet">Audit log</Link>}
          {isSuperAdmin && <Link to="/users" className="link-quiet">Users</Link>}
          <Link to="/applications" className="font-semibold text-parchment-100" aria-current="page">Applications</Link>
          <Link to="/settings" className="link-quiet">Security Settings</Link>
          <button type="button" onClick={handleLogout} className="link-quiet">Sign out</button>
        </nav>

        <div>
          <p className="eyebrow">Identity provider</p>
          <h1 className="font-display mt-1 text-3xl text-parchment-100">Applications</h1>
          <p className="font-serif mt-1 text-sm text-ash-400">
            Applications that sign users in with NovaForge. {isSuperAdmin ? "Role changes need your passkey." : "You have read-only access; a super admin makes changes."}
          </p>
        </div>

        {error && <Message error>{error}</Message>}
        {status && <Message>{status}</Message>}

        <section className="ledger-card">
          <div className="ledger-rule border-t-0 border-b border-solid p-5">
            <h2 className="font-display text-lg text-parchment-100">Registered applications</h2>
          </div>
          {loading ? (
            <p className="p-5 text-sm text-ash-400">Loading applications…</p>
          ) : apps.length === 0 ? (
            <p className="p-5 text-sm text-ash-400">
              No applications are registered yet. Register one with <code>scripts/iam.ts</code> or <code>POST /api/applications</code>.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="text-xs text-ash-400">
                    <th className="p-3 font-normal">Name</th>
                    <th className="p-3 font-normal">Client ID</th>
                    <th className="p-3 font-normal">Status</th>
                    <th className="p-3 font-normal">Roles</th>
                    <th className="p-3 font-normal">Assignments</th>
                    <th className="p-3 font-normal">Live grants</th>
                    <th className="p-3 font-normal"></th>
                  </tr>
                </thead>
                <tbody>
                  {apps.map((app) => (
                    <tr key={app.id} className="border-t border-iron-800">
                      <td className="p-3 text-parchment-100">{app.name}</td>
                      <td className="p-3 font-mono text-xs text-ash-400">{app.clientId}</td>
                      <td className="p-3 text-xs text-ash-300">{app.status}</td>
                      <td className="p-3 text-ash-300">{app._count.roles}</td>
                      <td className="p-3 text-ash-300">{app._count.assignments}</td>
                      <td className="p-3 text-ash-300">{app._count.grants}</td>
                      <td className="p-3 text-right">
                        <button
                          type="button"
                          className="link-quiet text-xs"
                          aria-expanded={selectedId === app.id}
                          onClick={() => setSelectedId(selectedId === app.id ? null : app.id)}
                        >
                          {selectedId === app.id ? "Close" : "Manage"}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {selectedId && (
          <AppPanel
            key={selectedId}
            appId={selectedId}
            canEdit={isSuperAdmin}
            onChanged={() => void loadApps()}
            onStatus={setStatus}
            onError={setError}
          />
        )}
      </div>
    </main>
  );
}

function AppPanel({
  appId,
  canEdit,
  onChanged,
  onStatus,
  onError,
}: {
  appId: string;
  canEdit: boolean;
  onChanged: () => void;
  onStatus: (message: string | null) => void;
  onError: (message: string | null) => void;
}) {
  const [detail, setDetail] = useState<AppDetail | null>(null);
  const [assignments, setAssignments] = useState<Assignment[]>([]);
  const [grants, setGrants] = useState<Grant[]>([]);
  const [users, setUsers] = useState<UserOption[]>([]);
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState({ userId: "", roleId: "", resource: "*", expiresAt: "" });

  const load = useCallback(async () => {
    try {
      const [d, a, g] = await Promise.all([
        apiGet<AppDetail>(`/applications/${appId}`),
        apiGet<Page<Assignment>>(`/applications/${appId}/assignments?pageSize=100`),
        apiGet<Page<Grant>>(`/applications/${appId}/grants?pageSize=100`),
      ]);
      setDetail(d);
      setAssignments(a.items);
      setGrants(g.items);
      if (canEdit) setUsers(await apiGet<UserOption[]>("/users"));
    } catch (err) {
      onError(describeError(err));
    }
  }, [appId, canEdit, onError]);

  useEffect(() => {
    void load();
  }, [load]);

  // Role changes need a fresh passkey assertion; revoking a live grant does not
  // (the server treats revocation as a safety-increasing action and only asks
  // for session trust), so it must not prompt for one.
  async function guarded(message: string, action: (response: unknown) => Promise<void>, stepUp = true) {
    onError(null);
    onStatus(null);
    setBusy(true);
    try {
      let response: unknown;
      if (stepUp) {
        onStatus("Confirm with your passkey…");
        response = await governanceProof(APPLICATION_STEP_UP_PATH);
      }
      await action(response);
      onStatus(message);
      await load();
      onChanged();
    } catch (err) {
      onStatus(null);
      onError(describeError(err));
    } finally {
      setBusy(false);
    }
  }

  function assign(e: FormEvent) {
    e.preventDefault();
    if (!form.userId || !form.roleId) return;
    void guarded("Role assigned.", async (response) => {
      await apiPost(`/applications/${appId}/assignments`, {
        userId: form.userId,
        roleId: form.roleId,
        resource: form.resource.trim() || "*",
        ...(form.expiresAt ? { expiresAt: new Date(form.expiresAt).toISOString() } : {}),
        response,
      });
      setForm({ userId: "", roleId: "", resource: "*", expiresAt: "" });
    });
  }

  function revokeAssignment(a: Assignment) {
    void guarded(`Revoked ${a.role.key} from ${a.user.email}.`, async (response) => {
      await apiDelete(`/applications/${appId}/assignments/${a.id}`, { response });
    });
  }

  function revokeGrant(g: Grant) {
    void guarded(
      "Grant revoked; the application's tokens for it stop working.",
      async () => {
        await apiDelete(`/applications/${appId}/grants/${g.id}`);
      },
      false,
    );
  }

  if (!detail) return <p className="text-sm text-ash-400" role="status">Loading application…</p>;

  return (
    <section className="ledger-card space-y-8 p-5" aria-label={`${detail.name} details`}>
      <div>
        <h2 className="font-display text-xl text-parchment-100">{detail.name}</h2>
        {detail.description && <p className="font-serif mt-1 text-sm text-ash-400">{detail.description}</p>}
        <dl className="mt-4 grid grid-cols-1 gap-x-8 gap-y-3 text-sm sm:grid-cols-2">
          <Field label="Client ID"><span className="font-mono text-xs">{detail.clientId}</span></Field>
          <Field label="Type / status">{detail.type} · {detail.status}</Field>
          <Field label="Audience"><span className="font-mono text-xs">{detail.audience}</span></Field>
          <Field label="Access token lifetime">{detail.accessTokenTtlSec}s</Field>
          <Field label="Requires an assigned role">{detail.requireAssignment ? "Yes" : "No"}</Field>
          <Field label="Scopes">{detail.allowedScopes.join(", ")}</Field>
          <Field label="Redirect URIs">
            <ul className="space-y-1 font-mono text-xs">{detail.redirectUris.map((u) => <li key={u} className="break-all">{u}</li>)}</ul>
          </Field>
          <Field label="Credentials">
            {detail.secrets.length === 0 ? "None" : (
              <ul className="space-y-1 text-xs">
                {detail.secrets.map((s) => (
                  <li key={s.id}>{s.label ?? "secret"} · created {new Date(s.createdAt).toLocaleDateString()} · {s.revokedAt ? "revoked" : "active"}</li>
                ))}
              </ul>
            )}
          </Field>
        </dl>
      </div>

      <div>
        <h3 className="font-display text-lg text-parchment-100">Roles</h3>
        {detail.roles.length === 0 ? (
          <p className="mt-2 text-sm text-ash-400">No roles defined.</p>
        ) : (
          <ul className="mt-2 divide-y divide-iron-800 text-sm">
            {detail.roles.map((r) => (
              <li key={r.id} className="py-2">
                <span className="text-parchment-100">{r.name}</span> <span className="font-mono text-xs text-ash-400">{r.key}</span>
                <span className="ml-2 text-xs text-ash-400">{r.assignmentCount} assigned</span>
                {r.permissions.length > 0 && <p className="mt-1 font-mono text-xs text-ash-400">{r.permissions.join(" · ")}</p>}
              </li>
            ))}
          </ul>
        )}
      </div>

      <div>
        <h3 className="font-display text-lg text-parchment-100">Assignments</h3>
        {assignments.length === 0 ? (
          <p className="mt-2 text-sm text-ash-400">Nobody holds a role in this application.</p>
        ) : (
          <div className="mt-2 overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="text-xs text-ash-400">
                  <th className="p-2 font-normal">User</th>
                  <th className="p-2 font-normal">Role</th>
                  <th className="p-2 font-normal">Resource</th>
                  <th className="p-2 font-normal">Expires</th>
                  <th className="p-2 font-normal"></th>
                </tr>
              </thead>
              <tbody>
                {assignments.map((a) => (
                  <tr key={a.id} className="border-t border-iron-800">
                    <td className="p-2 text-parchment-100">{a.user.name} <span className="text-xs text-ash-400">{a.user.email}</span></td>
                    <td className="p-2 font-mono text-xs text-ash-300">{a.role.key}</td>
                    <td className="p-2 font-mono text-xs text-ash-300">{a.resource}</td>
                    <td className="p-2 text-xs text-ash-400">{a.expiresAt ? new Date(a.expiresAt).toLocaleString() : "never"}</td>
                    <td className="p-2 text-right">
                      {canEdit && (
                        <button type="button" disabled={busy} onClick={() => revokeAssignment(a)} className="text-xs text-rust-400 underline decoration-iron-600 underline-offset-4 hover:text-rust-500">
                          Revoke
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {canEdit && detail.roles.length > 0 && (
          <form onSubmit={assign} className="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-5" aria-label="Assign a role">
            <label className="text-xs text-ash-300">
              User
              <select required value={form.userId} onChange={(e) => setForm({ ...form, userId: e.target.value })} className="mt-1 w-full rounded border border-iron-700 bg-iron-950 px-2 py-1.5 text-sm text-parchment-100">
                <option value="">Select…</option>
                {users.map((u) => <option key={u.id} value={u.id}>{u.name} ({u.email})</option>)}
              </select>
            </label>
            <label className="text-xs text-ash-300">
              Role
              <select required value={form.roleId} onChange={(e) => setForm({ ...form, roleId: e.target.value })} className="mt-1 w-full rounded border border-iron-700 bg-iron-950 px-2 py-1.5 text-sm text-parchment-100">
                <option value="">Select…</option>
                {detail.roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
              </select>
            </label>
            <label className="text-xs text-ash-300">
              Resource
              <input value={form.resource} onChange={(e) => setForm({ ...form, resource: e.target.value })} placeholder="* or a/b or a/*" className="mt-1 w-full rounded border border-iron-700 bg-iron-950 px-2 py-1.5 font-mono text-sm text-parchment-100" />
            </label>
            <label className="text-xs text-ash-300">
              Expires (optional)
              <input type="datetime-local" value={form.expiresAt} onChange={(e) => setForm({ ...form, expiresAt: e.target.value })} className="mt-1 w-full rounded border border-iron-700 bg-iron-950 px-2 py-1.5 text-sm text-parchment-100" />
            </label>
            <div className="flex items-end">
              <button type="submit" disabled={busy || !form.userId || !form.roleId} className="btn-primary w-full">{busy ? "Working…" : "Assign"}</button>
            </div>
          </form>
        )}
      </div>

      <div>
        <h3 className="font-display text-lg text-parchment-100">Live grants</h3>
        {grants.length === 0 ? (
          <p className="mt-2 text-sm text-ash-400">This application holds no active sessions.</p>
        ) : (
          <ul className="mt-2 divide-y divide-iron-800 text-sm">
            {grants.map((g) => (
              <li key={g.id} className="flex items-center justify-between gap-4 py-2">
                <span className="text-ash-300">
                  <span className="text-parchment-100">{g.user?.name ?? g.userId ?? "user"}</span>
                  <span className="ml-2 font-mono text-xs text-ash-400">{g.scope}</span>
                  <span className="ml-2 text-xs text-ash-400">since {new Date(g.createdAt).toLocaleString()}</span>
                </span>
                {canEdit && (
                  <button type="button" disabled={busy} onClick={() => revokeGrant(g)} className="text-xs text-rust-400 underline decoration-iron-600 underline-offset-4 hover:text-rust-500">
                    Revoke
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-xs text-ash-400">{label}</dt>
      <dd className="text-ash-300">{children}</dd>
    </div>
  );
}

function Message({ children, error }: { children: ReactNode; error?: boolean }) {
  return (
    <p
      role={error ? "alert" : "status"}
      className={`rounded border p-3 text-sm ${
        error ? "border-rust-500/40 bg-rust-500/10 text-rust-400" : "border-iron-700 bg-iron-900 text-parchment-100"
      }`}
    >
      {children}
    </p>
  );
}

function describeError(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return "Something went wrong.";
}
