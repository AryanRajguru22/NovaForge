import { useCallback, useEffect, useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ApiError, apiDelete, apiGet, apiPost, apiPut } from "../lib/api.js";

type Role = "ADMIN" | "SENIOR_APPROVER" | "APPROVER" | "MEMBER";
type QuorumType = "N_OF_M" | "ROLE_BASED" | "WEIGHTED";
interface Policy { id: string; actionType: string; quorumType: QuorumType; minApprovals: number; eligibleRoles: Role[]; fallbackPolicyId: string | null; escalationTimeoutSec: number }
interface FormState { actionType: string; quorumType: QuorumType; minApprovals: number; eligibleRoles: Role[]; fallbackPolicyId: string; escalationTimeoutSec: number }
const roles: Role[] = ["ADMIN", "SENIOR_APPROVER", "APPROVER", "MEMBER"];
const blankForm: FormState = { actionType: "", quorumType: "N_OF_M", minApprovals: 1, eligibleRoles: ["APPROVER"], fallbackPolicyId: "", escalationTimeoutSec: 300 };

export default function PolicyManagement() {
  const navigate = useNavigate();
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [form, setForm] = useState<FormState>(blankForm);
  const [editing, setEditing] = useState<Policy | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try { setPolicies(await apiGet<Policy[]>("/policies")); }
    catch (err) { if (err instanceof ApiError && err.status === 401) navigate("/login"); else setError(describeError(err)); }
    finally { setLoading(false); }
  }, [navigate]);
  useEffect(() => { void load(); }, [load]);

  function update<K extends keyof FormState>(key: K, value: FormState[K]) { setForm((current) => ({ ...current, [key]: value })); }
  function beginEdit(policy: Policy) { setEditing(policy); setForm({ actionType: policy.actionType, quorumType: policy.quorumType, minApprovals: policy.minApprovals, eligibleRoles: policy.eligibleRoles, fallbackPolicyId: policy.fallbackPolicyId ?? "", escalationTimeoutSec: policy.escalationTimeoutSec }); setError(null); setStatus(null); }
  function reset() { setEditing(null); setForm(blankForm); }
  async function submit(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setError(null); setStatus(null);
    const body = { ...form, fallbackPolicyId: form.fallbackPolicyId || null };
    try { if (editing) { await apiPut(`/policies/${editing.id}`, body); setStatus("Policy updated."); } else { await apiPost("/policies", body); setStatus("Policy created."); } reset(); await load(); }
    catch (err) { setError(describeError(err)); } finally { setBusy(false); }
  }
  async function remove(policy: Policy) {
    if (!window.confirm(`Delete the ${policy.actionType} policy?`)) return;
    setBusy(true); setError(null);
    try { await apiDelete(`/policies/${policy.id}`); if (editing?.id === policy.id) reset(); setStatus("Policy deleted."); await load(); }
    catch (err) { setError(describeError(err)); } finally { setBusy(false); }
  }

  return (
    <main className="min-h-screen p-5 sm:p-8">
      <div className="mx-auto max-w-5xl space-y-6">
        <nav className="ledger-rule flex gap-5 pb-4 text-sm text-ash-400">
          <Link to="/approvals" className="link-quiet">Approvals</Link>
          <Link to="/policies" className="font-semibold text-parchment-100">Policies</Link>
          <Link to="/audit" className="link-quiet">Audit log</Link>
          <Link to="/users" className="link-quiet">Users</Link>
          <Link to="/settings" className="link-quiet">Security settings</Link>
        </nav>
        <div>
          <p className="eyebrow">Governance</p>
          <h1 className="font-display mt-1 text-3xl text-parchment-100">Approval policies</h1>
          <p className="font-serif mt-1 text-sm text-ash-400">Define who can approve each sensitive action and when to escalate.</p>
        </div>
        {error && <Message error>{error}</Message>}
        {status && <Message>{status}</Message>}
        <div className="grid gap-6 lg:grid-cols-[1.15fr_.85fr]">
          <section className="ledger-card">
            <div className="ledger-rule border-t-0 border-b border-solid p-5">
              <h2 className="font-display text-lg text-parchment-100">Configured policies</h2>
            </div>
            {loading ? (
              <p className="p-5 text-sm text-ash-400">Loading policies…</p>
            ) : policies.length === 0 ? (
              <p className="p-5 text-sm text-ash-400">No policies have been created.</p>
            ) : (
              <ul className="divide-y divide-dashed divide-iron-700">
                {policies.map((policy) => (
                  <li key={policy.id} className="p-5">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <p className="font-medium text-parchment-100">{policy.actionType}</p>
                        <p className="mt-1 text-sm text-ash-400">
                          {policy.quorumType.replace(/_/g, " ")} · {policy.minApprovals} required · {policy.escalationTimeoutSec}s escalation
                        </p>
                        <p className="font-mono mt-1 text-xs text-ash-400">
                          {policy.eligibleRoles.map((role) => role.replace(/_/g, " ")).join(", ")}
                        </p>
                      </div>
                      <div className="flex gap-3 text-sm">
                        <button type="button" onClick={() => beginEdit(policy)} className="link-quiet">Edit</button>
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => void remove(policy)}
                          className="text-rust-400 underline decoration-iron-600 underline-offset-4 hover:text-rust-500 disabled:opacity-50"
                        >
                          Delete
                        </button>
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </section>
          <section className="ledger-card p-5">
            <div className="flex justify-between gap-3">
              <div>
                <h2 className="font-display text-lg text-parchment-100">{editing ? "Edit policy" : "Create policy"}</h2>
                <p className="font-serif mt-1 text-sm text-ash-400">Policy changes require an administrator account.</p>
              </div>
              {editing && <button type="button" onClick={reset} className="link-quiet text-sm">Cancel</button>}
            </div>
            <form onSubmit={submit} className="mt-5 space-y-4">
              <Field label="Action type">
                <input required value={form.actionType} onChange={(event) => update("actionType", event.target.value)} className="input" placeholder="TRANSFER_FUNDS" />
              </Field>
              <Field label="Quorum type">
                <select value={form.quorumType} onChange={(event) => update("quorumType", event.target.value as QuorumType)} className="input">
                  <option value="N_OF_M">N of M</option>
                  <option value="ROLE_BASED">Role based</option>
                  <option value="WEIGHTED">Weighted</option>
                </select>
              </Field>
              <Field label="Minimum approvals">
                <input required min="0" type="number" value={form.minApprovals} onChange={(event) => update("minApprovals", Number(event.target.value))} className="input" />
              </Field>
              <fieldset>
                <legend className="mb-2 text-sm text-ash-300">Eligible roles</legend>
                <div className="grid grid-cols-2 gap-2">
                  {roles.map((role) => (
                    <label key={role} className="flex items-center gap-2 text-sm text-ash-300">
                      <input
                        type="checkbox"
                        checked={form.eligibleRoles.includes(role)}
                        onChange={(event) => update("eligibleRoles", event.target.checked ? [...form.eligibleRoles, role] : form.eligibleRoles.filter((item) => item !== role))}
                        className="accent-ember-500"
                      />
                      {role.replace(/_/g, " ")}
                    </label>
                  ))}
                </div>
              </fieldset>
              <Field label="Fallback policy">
                <select value={form.fallbackPolicyId} onChange={(event) => update("fallbackPolicyId", event.target.value)} className="input">
                  <option value="">None — expire at timeout</option>
                  {policies.filter((policy) => policy.id !== editing?.id).map((policy) => (
                    <option key={policy.id} value={policy.id}>{policy.actionType}</option>
                  ))}
                </select>
              </Field>
              <Field label="Escalation timeout (seconds)">
                <input required min="1" type="number" value={form.escalationTimeoutSec} onChange={(event) => update("escalationTimeoutSec", Number(event.target.value))} className="input" />
              </Field>
              <button disabled={busy || form.eligibleRoles.length === 0} className="btn-primary w-full">
                {busy ? "Saving…" : editing ? "Save policy" : "Create policy"}
              </button>
            </form>
          </section>
        </div>
      </div>
    </main>
  );
}
function Field({ label, children }: { label: string; children: ReactNode }) {
  return <label className="block text-sm text-ash-300">{label}<span className="mt-1 block">{children}</span></label>;
}
function Message({ children, error }: { children: ReactNode; error?: boolean }) {
  return (
    <p className={`rounded border p-3 text-sm ${error ? "border-rust-500/40 bg-rust-500/10 text-rust-400" : "border-iron-700 bg-iron-900 text-ash-300"}`}>
      {children}
    </p>
  );
}
function describeError(err: unknown) { if (err instanceof ApiError) return err.message; if (err instanceof Error) return err.message; return "Something went wrong."; }
