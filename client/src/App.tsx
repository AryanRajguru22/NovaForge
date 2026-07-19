import { useEffect } from "react";
import { Route, Routes, Link } from "react-router-dom";
import Login from "./pages/Login.js";
import Settings from "./pages/Settings.js";
import ApprovalDashboard from "./pages/ApprovalDashboard.js";
import PolicyManagement from "./pages/PolicyManagement.js";
import AuditLog from "./pages/AuditLog.js";
import UserManagement from "./pages/UserManagement.js";
import { refreshSession } from "./lib/api.js";

// Under the 15-minute access token lifetime so a session gets renewed before
// it ever has to rely on the reactive 401-retry in lib/api.ts -- and so an
// idle-but-open tab still "checks back in" periodically, which is what lets
// Session.trustLevel actually decay/recover the way it's designed to instead
// of sitting frozen at whatever it was on last login. Safe to run whether or
// not anyone's logged in: with no refresh cookie the call just no-ops.
const SESSION_REFRESH_INTERVAL_MS = 4 * 60 * 1000;

function Home() {
  return (
    <div className="min-h-screen">
      <div className="mx-auto flex min-h-screen max-w-5xl flex-col justify-center px-6 py-20">
        <p className="eyebrow mb-6">Passwordless auth · Approval-policy engine</p>

        <h1 className="font-display text-[15vw] leading-[0.85] tracking-tight text-parchment-100 sm:text-8xl">
          Nova<span className="text-ember-500">Forge</span>
        </h1>

        <p className="font-serif mt-8 max-w-xl text-lg leading-relaxed text-ash-300 text-balance">
          Every sign-in proves a key, not a password. Every sensitive action sits in the fire until
          enough signed hands have touched it — then it's struck, sealed, and written to a ledger
          nobody can quietly edit.
        </p>

        <div className="mt-10 flex flex-wrap items-center gap-x-8 gap-y-3">
          <Link to="/login" className="btn-primary">
            Sign in with a passkey
          </Link>
          <Link to="/approvals" className="link-quiet text-sm">
            Approval dashboard
          </Link>
          <Link to="/audit" className="link-quiet text-sm">
            Audit log
          </Link>
          <Link to="/users" className="link-quiet text-sm">
            User roles
          </Link>
          <Link to="/settings" className="link-quiet text-sm">
            Security settings
          </Link>
        </div>

        <div className="ledger-rule mt-16 grid grid-cols-1 gap-8 pt-8 sm:grid-cols-3">
          <Ledger index="I" title="Anchor" body="Passkeys, WebAuthn-signed. No password ever leaves the device." />
          <Ledger index="II" title="Quorum" body="N-of-M or role-based approval before any sensitive action clears." />
          <Ledger index="III" title="Ledger" body="Hash-chained audit trail — tamper anywhere, break the chain everywhere after." />
        </div>
      </div>
    </div>
  );
}

function Ledger({ index, title, body }: { index: string; title: string; body: string }) {
  return (
    <div>
      <p className="font-mono text-xs text-ember-500">{index}</p>
      <h3 className="font-display mt-1 text-xl text-parchment-100">{title}</h3>
      <p className="font-serif mt-1 text-sm leading-relaxed text-ash-400">{body}</p>
    </div>
  );
}

export default function App() {
  useEffect(() => {
    void refreshSession();
    const interval = setInterval(() => void refreshSession(), SESSION_REFRESH_INTERVAL_MS);
    return () => clearInterval(interval);
  }, []);

  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/login" element={<Login />} />
      <Route path="/approvals" element={<ApprovalDashboard />} />
      <Route path="/policies" element={<PolicyManagement />} />
      <Route path="/audit" element={<AuditLog />} />
      <Route path="/users" element={<UserManagement />} />
      <Route path="/settings" element={<Settings />} />
    </Routes>
  );
}
