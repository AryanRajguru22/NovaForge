import { useCallback, useEffect, useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ApiError, apiGet, apiPatch } from "../lib/api.js";
import { useAuth } from "../lib/auth.js";

type Role = "SUPER_ADMIN" | "ADMIN" | "SENIOR_APPROVER" | "APPROVER" | "MEMBER";
const roles: Role[] = ["SUPER_ADMIN", "ADMIN", "SENIOR_APPROVER", "APPROVER", "MEMBER"];

interface UserRow {
  id: string;
  email: string;
  name: string;
  role: Role;
  voteWeight: number;
  createdAt: string;
}

interface MeResponse {
  id: string;
  role: Role;
}

export default function UserManagement() {
  const navigate = useNavigate();
  const { user: authUser, refresh, logout } = useAuth();
  const [me, setMe] = useState<MeResponse | null>(null);
  const [users, setUsers] = useState<UserRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [savingId, setSavingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const [meResponse, usersResponse] = await Promise.all([
        apiGet<MeResponse>("/auth/me"),
        apiGet<UserRow[]>("/users"),
      ]);
      setMe(meResponse);
      setUsers(usersResponse);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        await refresh();
        navigate("/login", { replace: true });
      } else setError(describeError(err));
    } finally {
      setLoading(false);
    }
  }, [navigate, refresh]);

  useEffect(() => {
    void load();
  }, [load]);

  async function changeRole(user: UserRow, role: Role) {
    if (role === user.role) return;
    setError(null);
    setStatus(null);
    setSavingId(user.id);
    try {
      await apiPatch(`/users/${user.id}/role`, { role });
      setUsers((current) => current.map((u) => (u.id === user.id ? { ...u, role } : u)));
      setStatus(`${user.name}'s role changed to ${role}.`);
    } catch (err) {
      setError(describeError(err));
    } finally {
      setSavingId(null);
    }
  }

  async function changeWeight(user: UserRow, voteWeight: number) {
    if (!Number.isInteger(voteWeight) || voteWeight < 1 || voteWeight > 10 || voteWeight === user.voteWeight) return;
    setError(null);
    setStatus(null);
    setSavingId(user.id);
    try {
      await apiPatch(`/users/${user.id}/weight`, { voteWeight });
      setUsers((current) => current.map((u) => (u.id === user.id ? { ...u, voteWeight } : u)));
      setStatus(`${user.name}'s vote weight changed to ${voteWeight}.`);
    } catch (err) {
      setError(describeError(err));
    } finally {
      setSavingId(null);
    }
  }

  async function handleLogout() {
    await logout();
    navigate("/login", { replace: true });
  }

  return (
    <main className="min-h-screen p-5 sm:p-8">
      <div className="mx-auto max-w-5xl space-y-6">
        <nav className="ledger-rule flex flex-wrap items-center gap-x-5 gap-y-1 pb-4 text-sm text-ash-400 [&_a]:whitespace-nowrap [&_button]:whitespace-nowrap">
          <Link to="/approvals" className="link-quiet">Approvals</Link>
          <Link to="/policies" className="link-quiet">Policies</Link>
          {authUser?.role === "SUPER_ADMIN" && <Link to="/audit" className="link-quiet">Audit log</Link>}
          {authUser?.role === "SUPER_ADMIN" && <Link to="/users" className="font-semibold text-parchment-100">Users</Link>}
          <Link to="/settings" className="link-quiet">Security Settings</Link>
          <button type="button" onClick={handleLogout} className="link-quiet">Sign out</button>
        </nav>

        <div>
          <p className="eyebrow">Governance</p>
          <h1 className="font-display mt-1 text-3xl text-parchment-100">User roles</h1>
          <p className="font-serif mt-1 text-sm text-ash-400">
            Only a super admin can change a user's role, vote weight, or view the audit log. Vote
            weight only matters for WEIGHTED-quorum policies, where each approver's vote counts
            for this many points toward the policy's threshold.
          </p>
        </div>

        {error && <Message error>{error}</Message>}
        {status && <Message>{status}</Message>}

        <section className="ledger-card">
          <div className="ledger-rule border-t-0 border-b border-solid p-5">
            <h2 className="font-display text-lg text-parchment-100">Accounts</h2>
          </div>

          {loading ? (
            <p className="p-5 text-sm text-ash-400">Loading users…</p>
          ) : users.length === 0 ? (
            <p className="p-5 text-sm text-ash-400">No users found.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="text-xs text-ash-400">
                    <th className="p-3 font-normal">Name</th>
                    <th className="p-3 font-normal">Email</th>
                    <th className="p-3 font-normal">Role</th>
                    <th className="p-3 font-normal">Vote weight</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((user) => (
                    <tr key={user.id} className="border-t border-iron-800">
                      <td className="p-3 text-parchment-100">
                        {user.name}
                        {me?.id === user.id && <span className="ml-2 text-xs text-ash-400">(you)</span>}
                      </td>
                      <td className="p-3 text-xs text-ash-400">{user.email}</td>
                      <td className="p-3">
                        <select
                          value={user.role}
                          disabled={savingId === user.id}
                          onChange={(e) => changeRole(user, e.target.value as Role)}
                          className="rounded border border-iron-700 bg-iron-950 px-2 py-1 text-sm text-parchment-100"
                        >
                          {roles.map((role) => (
                            <option key={role} value={role}>
                              {role}
                            </option>
                          ))}
                        </select>
                      </td>
                      <td className="p-3">
                        <input
                          type="number"
                          min={1}
                          max={10}
                          value={user.voteWeight}
                          disabled={savingId === user.id}
                          onChange={(e) => changeWeight(user, Number(e.target.value))}
                          className="w-16 rounded border border-iron-700 bg-iron-950 px-2 py-1 text-sm text-parchment-100"
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </main>
  );
}

function Message({ children, error }: { children: ReactNode; error?: boolean }) {
  return (
    <p
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
