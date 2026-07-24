import { useCallback, useEffect, useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ApiError, apiGet } from "../lib/api.js";
import { useAuth } from "../lib/auth.js";

interface AuditActor {
  id: string;
  name: string;
  email: string;
  role: string;
}

interface AuditEntry {
  id: string;
  entityType: string;
  entityId: string;
  event: string;
  actorId: string | null;
  actor: AuditActor | null;
  metadata: unknown;
  timestamp: string;
  prevHash: string | null;
  hash: string;
}

interface VerifyResult {
  valid: boolean;
  brokenAt?: string;
}

function short(hash: string | null): string {
  if (!hash) return "genesis";
  return `${hash.slice(0, 8)}…${hash.slice(-4)}`;
}

export default function AuditLog() {
  const navigate = useNavigate();
  const { user, refresh, logout } = useAuth();
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [verify, setVerify] = useState<VerifyResult | null>(null);
  const [verifying, setVerifying] = useState(false);

  const load = useCallback(async () => {
    setError(null);
    try {
      const page = await apiGet<{ entries: AuditEntry[]; nextCursor: string | null }>("/audit");
      setEntries(page.entries);
      setNextCursor(page.nextCursor);
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

  async function loadMore() {
    if (!nextCursor) return;
    setLoadingMore(true);
    setError(null);
    try {
      const page = await apiGet<{ entries: AuditEntry[]; nextCursor: string | null }>(
        `/audit?cursor=${nextCursor}`,
      );
      setEntries((current) => [...current, ...page.entries]);
      setNextCursor(page.nextCursor);
    } catch (err) {
      setError(describeError(err));
    } finally {
      setLoadingMore(false);
    }
  }

  async function runVerify() {
    setVerifying(true);
    setError(null);
    try {
      setVerify(await apiGet<VerifyResult>("/audit/verify"));
    } catch (err) {
      setError(describeError(err));
    } finally {
      setVerifying(false);
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
          {user?.role === "SUPER_ADMIN" && <Link to="/audit" className="font-semibold text-parchment-100">Audit log</Link>}
          {user?.role === "SUPER_ADMIN" && <Link to="/users" className="link-quiet">Users</Link>}
          <Link to="/settings" className="link-quiet">Security Settings</Link>
          <button type="button" onClick={handleLogout} className="link-quiet">Sign out</button>
        </nav>

        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <p className="eyebrow">Ledger</p>
            <h1 className="font-display mt-1 text-3xl text-parchment-100">Audit log</h1>
            <p className="font-serif mt-1 text-sm text-ash-400">
              Every sensitive event, hash-chained — each row's hash covers the previous row's
              hash, so rewriting history means rewriting every row after it.
            </p>
          </div>
          <button type="button" onClick={runVerify} disabled={verifying} className="btn-primary">
            {verifying ? "Verifying…" : "Verify chain integrity"}
          </button>
        </div>

        {error && <Message error>{error}</Message>}

        {verify && (
          <Message error={!verify.valid}>
            {verify.valid
              ? "Chain intact — every row's hash matches its recorded predecessor."
              : `Chain broken at row ${verify.brokenAt} — a row's hash no longer matches what its successor recorded.`}
          </Message>
        )}

        <section className="ledger-card">
          <div className="ledger-rule border-t-0 border-b border-solid p-5">
            <h2 className="font-display text-lg text-parchment-100">Entries</h2>
          </div>

          {loading ? (
            <p className="p-5 text-sm text-ash-400">Loading audit log…</p>
          ) : entries.length === 0 ? (
            <p className="p-5 text-sm text-ash-400">No audit events recorded yet.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="text-xs text-ash-400">
                    <th className="p-3 font-normal">Time</th>
                    <th className="p-3 font-normal">Event</th>
                    <th className="p-3 font-normal">Entity</th>
                    <th className="p-3 font-normal">Actor</th>
                    <th className="p-3 font-normal">Hash</th>
                    <th className="p-3 font-normal">Prev hash</th>
                  </tr>
                </thead>
                <tbody>
                  {entries.map((entry) => (
                    <tr key={entry.id} className="border-t border-iron-800">
                      <td className="p-3 text-xs text-ash-400">
                        {new Date(entry.timestamp).toLocaleString()}
                      </td>
                      <td className="p-3 text-parchment-100">{entry.event}</td>
                      <td className="p-3 font-mono text-xs text-ash-400">
                        {entry.entityType}/{entry.entityId.slice(0, 8)}
                      </td>
                      <td className="p-3 text-xs text-ash-400">
                        {entry.actor ? `${entry.actor.name} · ${entry.actor.role}` : "system"}
                      </td>
                      <td className="p-3 font-mono text-xs text-ember-500" title={entry.hash}>
                        {short(entry.hash)}
                      </td>
                      <td className="p-3 font-mono text-xs text-ash-400" title={entry.prevHash ?? undefined}>
                        {short(entry.prevHash)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {nextCursor && (
            <div className="border-t border-iron-800 p-4">
              <button
                type="button"
                onClick={loadMore}
                disabled={loadingMore}
                className="link-quiet text-sm"
              >
                {loadingMore ? "Loading…" : "Load more"}
              </button>
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
