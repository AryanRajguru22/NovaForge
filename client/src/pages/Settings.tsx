import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import QRCode from "qrcode";
import { apiGet, apiPost, ApiError } from "../lib/api.js";

interface MeResponse {
  id: string;
  email: string;
  name: string;
  role: string;
}

interface TotpSetupResponse {
  secret: string;
  otpauthUrl: string;
}

export default function Settings() {
  const navigate = useNavigate();
  const [user, setUser] = useState<MeResponse | null>(null);
  const [pendingSetup, setPendingSetup] = useState<TotpSetupResponse | null>(null);
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [enrolled, setEnrolled] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    apiGet<MeResponse>("/auth/me")
      .then(setUser)
      .catch(() => navigate("/login"));
  }, [navigate]);

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
      setEnrolled(true);
      setPendingSetup(null);
      setQrDataUrl(null);
      setStatus("Authenticator app enabled — you can now sign in with a 6-digit code as a fallback.");
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
    }
  }

  if (!user) {
    return <div className="p-8 text-slate-100">Loading…</div>;
  }

  return (
    <div className="min-h-screen bg-slate-950 p-8 text-slate-100">
      <div className="mx-auto max-w-md space-y-6">
        <div>
          <h1 className="text-xl font-semibold">Security settings</h1>
          <p className="text-sm text-slate-400">{user.email}</p>
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-900 p-6 space-y-4">
          <div>
            <h2 className="font-medium">Authenticator app (TOTP fallback)</h2>
            <p className="text-sm text-slate-400">
              Use as a backup sign-in method when your passkey device isn't available.
            </p>
          </div>

          {enrolled && (
            <p className="text-sm text-emerald-400">Authenticator app is enabled.</p>
          )}

          {!pendingSetup && !enrolled && (
            <button
              type="button"
              onClick={handleStartSetup}
              disabled={busy}
              className="rounded bg-slate-100 px-3 py-2 text-sm font-medium text-slate-950 disabled:opacity-50"
            >
              Set up authenticator app
            </button>
          )}

          {pendingSetup && (
            <div className="space-y-3">
              {qrDataUrl && (
                <img src={qrDataUrl} alt="Scan with your authenticator app" className="rounded bg-white p-2" />
              )}
              <p className="break-all text-xs text-slate-500">
                Can't scan? Enter this key manually: {pendingSetup.secret}
              </p>
              <form onSubmit={handleVerify} className="space-y-3">
                <div>
                  <label htmlFor="code" className="mb-1 block text-sm text-slate-300">
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
                    className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-slate-500"
                  />
                </div>
                <button
                  type="submit"
                  disabled={busy}
                  className="w-full rounded bg-slate-100 px-3 py-2 text-sm font-medium text-slate-950 disabled:opacity-50"
                >
                  Confirm and enable
                </button>
              </form>
            </div>
          )}

          {status && <p className="text-sm text-slate-400">{status}</p>}
          {error && <p className="text-sm text-red-400">{error}</p>}
        </div>
      </div>
    </div>
  );
}

function describeError(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return "Something went wrong.";
}
