import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { startRegistration, startAuthentication } from "@simplewebauthn/browser";
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/types";
import { apiPost, ApiError } from "../lib/api.js";

type Mode = "login" | "register" | "totp" | "recovery";

interface MeResponse {
  id: string;
  email: string;
  name: string;
  role: string;
}

export default function Login() {
  const navigate = useNavigate();
  const [mode, setMode] = useState<Mode>("login");
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [code, setCode] = useState("");
  const [recoveryCode, setRecoveryCode] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleRegister(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      setStatus("Requesting registration challenge…");
      const options = await apiPost<PublicKeyCredentialCreationOptionsJSON>(
        "/auth/register/options",
        { email, name },
      );

      setStatus("Waiting for your device (fingerprint, face, or security key)…");
      const response = await startRegistration(options);

      setStatus("Verifying with server…");
      await apiPost("/auth/register/verify", { email, response, deviceLabel: "Passkey" });

      setStatus("Passkey registered — you can now log in.");
      setMode("login");
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
      setStatus(null);
    }
  }

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      setStatus("Requesting login challenge…");
      const options = await apiPost<PublicKeyCredentialRequestOptionsJSON>("/auth/login/options", {
        email,
      });

      setStatus("Waiting for your device…");
      const response = await startAuthentication(options);

      setStatus("Verifying with server…");
      await apiPost<{ user: MeResponse }>("/auth/login/verify", { email, response });

      navigate("/approvals");
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
      setStatus(null);
    }
  }

  async function handleTotpLogin(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      setStatus("Verifying code…");
      await apiPost<{ user: MeResponse }>("/auth/login/totp", { email, token: code });
      navigate("/approvals");
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
      setStatus(null);
    }
  }

  async function handleRecoveryLogin(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      setStatus("Verifying recovery code…");
      await apiPost<{ user: MeResponse }>("/auth/login/recovery-code", {
        email,
        code: recoveryCode,
      });
      navigate("/approvals");
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
      setStatus(null);
    }
  }

  const titles: Record<Mode, string> = {
    login: "Sign in with your passkey",
    register: "Register a new passkey",
    totp: "Sign in with your authenticator app",
    recovery: "Sign in with a recovery code",
  };

  const submitLabels: Record<Mode, string> = {
    login: "Sign in",
    register: "Register passkey",
    totp: "Verify code",
    recovery: "Use recovery code",
  };

  const handlers: Record<Mode, (e: React.FormEvent) => Promise<void>> = {
    login: handleLogin,
    register: handleRegister,
    totp: handleTotpLogin,
    recovery: handleRecoveryLogin,
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950 text-slate-100">
      <div className="w-full max-w-sm space-y-6 rounded-lg border border-slate-800 bg-slate-900 p-8">
        <div>
          <h1 className="text-xl font-semibold">NovaForge</h1>
          <p className="text-sm text-slate-400">{titles[mode]}</p>
        </div>

        <form onSubmit={handlers[mode]} className="space-y-4">
          <div>
            <label htmlFor="email" className="mb-1 block text-sm text-slate-300">
              Email
            </label>
            <input
              id="email"
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-slate-500"
            />
          </div>

          {mode === "register" && (
            <div>
              <label htmlFor="name" className="mb-1 block text-sm text-slate-300">
                Name
              </label>
              <input
                id="name"
                type="text"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-slate-500"
              />
            </div>
          )}

          {mode === "totp" && (
            <div>
              <label htmlFor="code" className="mb-1 block text-sm text-slate-300">
                6-digit code
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
          )}

          {mode === "recovery" && (
            <div>
              <label htmlFor="recoveryCode" className="mb-1 block text-sm text-slate-300">
                Recovery code
              </label>
              <input
                id="recoveryCode"
                type="text"
                placeholder="XXXX-XXXX"
                required
                value={recoveryCode}
                onChange={(e) => setRecoveryCode(e.target.value)}
                className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-slate-500"
              />
            </div>
          )}

          <button
            type="submit"
            disabled={busy}
            className="w-full rounded bg-slate-100 px-3 py-2 text-sm font-medium text-slate-950 disabled:opacity-50"
          >
            {submitLabels[mode]}
          </button>
        </form>

        {status && <p className="text-sm text-slate-400">{status}</p>}
        {error && <p className="text-sm text-red-400">{error}</p>}

        <div className="flex flex-col gap-2 text-sm">
          {mode !== "register" && (
            <button
              type="button"
              onClick={() => {
                setMode("register");
                setError(null);
              }}
              className="text-slate-400 underline hover:text-slate-200"
            >
              New here? Register a passkey
            </button>
          )}
          {mode !== "login" && (
            <button
              type="button"
              onClick={() => {
                setMode("login");
                setError(null);
              }}
              className="text-slate-400 underline hover:text-slate-200"
            >
              Already registered? Sign in with a passkey
            </button>
          )}
          {mode !== "totp" && (
            <button
              type="button"
              onClick={() => {
                setMode("totp");
                setError(null);
              }}
              className="text-slate-400 underline hover:text-slate-200"
            >
              Don't have your passkey device? Use an authenticator code
            </button>
          )}
          {mode !== "recovery" && (
            <button
              type="button"
              onClick={() => {
                setMode("recovery");
                setError(null);
              }}
              className="text-slate-400 underline hover:text-slate-200"
            >
              Lost everything? Use a recovery code
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

function describeError(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) {
    if (err.name === "NotAllowedError") {
      return "Passkey action was cancelled or timed out.";
    }
    return err.message;
  }
  return "Something went wrong.";
}
