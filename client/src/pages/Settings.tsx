import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import QRCode from "qrcode";
import { startAuthentication } from "@simplewebauthn/browser";
import type { PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/types";
import { apiGet, apiPost, apiDelete, apiPatch, ApiError } from "../lib/api.js";

interface MeResponse {
  id: string;
  email: string;
  name: string;
  role: string;
  factors: {
    passkey: boolean;
    totp: boolean;
    recoveryCodes: number;
  };
  totpLoginEnabled: boolean;
  recoveryCodeLoginEnabled: boolean;
}

interface TotpSetupResponse {
  secret: string;
  otpauthUrl: string;
}

interface SessionInfo {
  id: string;
  deviceId: string;
  trustLevel: number;
  createdAt: string;
  expiresAt: string;
  lastVerifiedAt: string;
  current: boolean;
}

export default function Settings() {
  const navigate = useNavigate();
  const [user, setUser] = useState<MeResponse | null>(null);

  // TOTP enrollment
  const [pendingSetup, setPendingSetup] = useState<TotpSetupResponse | null>(null);
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [code, setCode] = useState("");

  // Recovery codes
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);

  // Sessions
  const [sessions, setSessions] = useState<SessionInfo[] | null>(null);

  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    refreshUser();
    refreshSessions();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [navigate]);

  async function refreshUser() {
    try {
      setUser(await apiGet<MeResponse>("/auth/me"));
    } catch {
      navigate("/login");
    }
  }

  async function refreshSessions() {
    try {
      setSessions(await apiGet<SessionInfo[]>("/auth/sessions"));
    } catch {
      // session list is a nice-to-have; ignore failures here so the rest of
      // the page (which already redirects on auth failure) still renders
    }
  }

  async function handleStartSetup() {
    setError(null);
    setBusy(true);
    try {
      const setup = await apiPost<TotpSetupResponse>("/auth/totp/setup", {});
      setPendingSetup(setup);
      setQrDataUrl(await QRCode.toDataURL(setup.otpauthUrl));
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
    }
  }

  async function handleVerify(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await apiPost("/auth/totp/verify", { token: code });
      await refreshUser();
      setPendingSetup(null);
      setQrDataUrl(null);
      setCode("");
      setStatus("Authenticator app enabled — you can now sign in with a 6-digit code as a fallback.");
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
    }
  }

  async function handleGenerateRecoveryCodes() {
    setError(null);
    setBusy(true);
    try {
      setStatus("Requesting verification challenge…");
      const options = await apiPost<PublicKeyCredentialRequestOptionsJSON>("/auth/recovery-codes/options", {});

      setStatus("Confirm with your passkey to generate new codes…");
      const response = await startAuthentication(options);

      setStatus("Verifying…");
      const { codes } = await apiPost<{ codes: string[] }>("/auth/recovery-codes/generate", { response });
      setRecoveryCodes(codes);
      setStatus("New recovery codes generated — any older codes no longer work.");
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
    }
  }

  async function handleRevokeSession(id: string) {
    setError(null);
    try {
      await apiDelete(`/auth/sessions/${id}`);
      if (sessions?.find((s) => s.id === id)?.current) {
        navigate("/login");
        return;
      }
      await refreshSessions();
    } catch (err) {
      setError(describeError(err));
    }
  }

  async function handleLoginMethodChange(
    field: "totpLoginEnabled" | "recoveryCodeLoginEnabled",
    enabled: boolean,
  ) {
    setError(null);
    setBusy(true);
    try {
      await apiPatch("/auth/preferences", { [field]: enabled });
      await refreshUser();
      setStatus(`${field === "totpLoginEnabled" ? "Authenticator app" : "Recovery-code"} login ${enabled ? "enabled" : "disabled"}.`);
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
    }
  }

  if (!user) {
    return <div className="font-mono p-8 text-sm text-ash-400">Loading…</div>;
  }

  return (
    <div className="min-h-screen px-6 py-8">
      <div className="mx-auto max-w-md space-y-6">
        <nav className="ledger-rule flex items-center gap-5 pb-4 text-sm text-ash-400">
          <Link to="/approvals" className="link-quiet">
            Approvals
          </Link>
          <Link to="/policies" className="link-quiet">
            Policies
          </Link>
          <Link to="/settings" className="font-semibold text-parchment-100">
            Security Settings
          </Link>
        </nav>
        <div>
          <p className="eyebrow">Account</p>
          <h1 className="font-display mt-1 text-2xl text-parchment-100">Security settings</h1>
          <p className="font-mono text-xs text-ash-400">{user.email}</p>
        </div>

        <div className="ledger-card space-y-4 p-6">
          <div>
            <h2 className="font-display text-lg text-parchment-100">Authenticator app (TOTP fallback)</h2>
            <p className="font-serif text-sm text-ash-400">
              Use as a backup sign-in method when your passkey device isn't available.
            </p>
          </div>

          {user.factors.totp && !pendingSetup && (
            <p className="text-sm text-temper-400">Authenticator app is enabled.</p>
          )}

          {!pendingSetup && (
            <button type="button" onClick={handleStartSetup} disabled={busy} className="btn-primary">
              {user.factors.totp ? "Replace with a new device" : "Set up authenticator app"}
            </button>
          )}

          {user.factors.totp && !pendingSetup && (
            <p className="text-xs text-ash-400">
              Setting up a new device replaces the current one — the old QR code/secret stops
              working immediately.
            </p>
          )}

          {pendingSetup && (
            <div className="space-y-3">
              {qrDataUrl && (
                <img src={qrDataUrl} alt="Scan with your authenticator app" className="rounded bg-parchment-100 p-2" />
              )}
              <p className="font-mono break-all text-xs text-ash-400">
                Can't scan? Enter this key manually: {pendingSetup.secret}
              </p>
              <form onSubmit={handleVerify} className="space-y-3">
                <div>
                  <label htmlFor="code" className="mb-1 block text-sm text-ash-300">
                    Enter the 6-digit code
                  </label>
                  <input
                    id="code"
                    inputMode="numeric"
                    pattern="[0-9]{6}"
                    maxLength={6}
                    required
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    className="input font-mono tracking-[0.3em]"
                  />
                </div>
                <button type="submit" disabled={busy} className="btn-primary w-full">
                  Confirm and enable
                </button>
              </form>
            </div>
          )}
        </div>

        <div className="ledger-card space-y-4 p-6">
          <div>
            <h2 className="font-display text-lg text-parchment-100">Recovery codes</h2>
            <p className="font-serif text-sm text-ash-400">
              One-time codes for when neither your passkey nor authenticator app is available.
              Generating new codes requires your passkey and invalidates any previous ones.
            </p>
          </div>

          <button type="button" onClick={handleGenerateRecoveryCodes} disabled={busy} className="btn-primary">
            {recoveryCodes ? "Generate new codes" : "Generate recovery codes"}
          </button>

          {recoveryCodes && (
            <div className="space-y-2">
              <p className="text-xs text-ember-400">
                Save these now — they won't be shown again. Each code works once.
              </p>
              <div className="grid grid-cols-2 gap-2 rounded border border-iron-600 bg-iron-950 p-3 font-mono text-sm text-parchment-100">
                {recoveryCodes.map((c) => (
                  <span key={c}>{c}</span>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="ledger-card space-y-4 p-6">
          <div>
            <h2 className="font-display text-lg text-parchment-100">Login methods</h2>
            <p className="font-serif text-sm text-ash-400">
              Keep a backup method enrolled, but turn off its ability to sign in whenever you want.
            </p>
          </div>

          <div className="rounded border border-iron-700 bg-iron-950 p-3 text-sm">
            <p className="font-medium text-parchment-100">Passkey</p>
            <p className="mt-1 text-ash-400">Always enabled — this is your required primary sign-in method.</p>
          </div>

          <LoginMethodToggle
            label="Authenticator app (TOTP)"
            description="Allow the enrolled authenticator app to be used as a fallback sign-in method."
            enabled={user.totpLoginEnabled}
            available={user.factors.totp}
            busy={busy}
            onChange={(enabled) => handleLoginMethodChange("totpLoginEnabled", enabled)}
          />

          <LoginMethodToggle
            label="Recovery codes"
            description="Allow your unused recovery codes to be used as a fallback sign-in method."
            enabled={user.recoveryCodeLoginEnabled}
            available={user.factors.recoveryCodes > 0}
            busy={busy}
            onChange={(enabled) => handleLoginMethodChange("recoveryCodeLoginEnabled", enabled)}
          />
        </div>

        <div className="ledger-card space-y-4 p-6">
          <div>
            <h2 className="font-display text-lg text-parchment-100">Active sessions</h2>
            <p className="font-serif text-sm text-ash-400">
              Devices currently signed in. Trust decays if a session goes too long without
              reconnecting to the server (e.g. poor connectivity).
            </p>
          </div>

          {!sessions && <p className="text-sm text-ash-400">Loading sessions…</p>}

          {sessions && sessions.length === 0 && (
            <p className="text-sm text-ash-400">No active sessions.</p>
          )}

          {sessions && sessions.length > 0 && (
            <ul className="space-y-2">
              {sessions.map((s) => (
                <li
                  key={s.id}
                  className="flex items-center justify-between rounded border border-iron-700 bg-iron-950 p-3 text-sm"
                >
                  <div>
                    <p className="text-parchment-100">
                      {s.current ? "This device" : "Other device"}{" "}
                      <span className="font-mono text-xs text-ash-400">· trust {s.trustLevel}%</span>
                    </p>
                    <p className="text-xs text-ash-400">
                      Last verified {new Date(s.lastVerifiedAt).toLocaleString()}
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleRevokeSession(s.id)}
                    className="text-xs text-rust-400 underline decoration-iron-600 underline-offset-4 hover:text-rust-500"
                  >
                    Revoke
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

        {status && <p className="font-mono text-xs text-ash-400">{status}</p>}
        {error && <p className="font-mono text-xs text-rust-400">{error}</p>}
      </div>
    </div>
  );
}

function LoginMethodToggle({
  label,
  description,
  enabled,
  available,
  busy,
  onChange,
}: {
  label: string;
  description: string;
  enabled: boolean;
  available: boolean;
  busy: boolean;
  onChange: (enabled: boolean) => void;
}) {
  const disabled = !available || busy;
  return (
    <div className={`flex items-center justify-between gap-4 rounded border border-iron-700 bg-iron-950 p-3 ${!available ? "opacity-50" : ""}`}>
      <div>
        <p className="text-sm font-medium text-parchment-100">{label}</p>
        <p className="mt-1 text-xs text-ash-400">{available ? description : "Set up this method above before it can be used for sign-in."}</p>
      </div>
      <button
        type="button"
        role="switch"
        aria-checked={enabled}
        aria-label={`${label} login ${enabled ? "enabled" : "disabled"}`}
        disabled={disabled}
        onClick={() => onChange(!enabled)}
        className={`shrink-0 rounded-full px-3 py-1.5 font-mono text-xs font-medium transition-colors disabled:cursor-not-allowed ${enabled ? "bg-temper-500 text-iron-950" : "bg-iron-700 text-ash-300"}`}
      >
        {enabled ? "On" : "Off"}
      </button>
    </div>
  );
}

function describeError(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return "Something went wrong.";
}
