import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { startRegistration, startAuthentication } from "@simplewebauthn/browser";
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/types";
import { apiPost, ApiError } from "../lib/api.js";
import { useAuth } from "../lib/auth.js";

type Mode = "login" | "register" | "totp" | "recovery";

interface MeResponse {
  id: string;
  email: string;
  name: string;
  role: string;
}

export default function Login() {
  const navigate = useNavigate();
  const { refresh } = useAuth();
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

      await refresh();
      navigate("/approvals", { replace: true });
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
      await refresh();
      navigate("/approvals", { replace: true });
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
      await refresh();
      navigate("/approvals", { replace: true });
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
    <div className="flex min-h-screen items-center justify-center px-6">
      <div className="ledger-card w-full max-w-sm space-y-6 p-8">
        <div>
          <p className="eyebrow">NovaForge</p>
          <h1 className="font-display mt-1 text-2xl text-parchment-100">{titles[mode]}</h1>
        </div>

        <form onSubmit={handlers[mode]} className="space-y-4">
          <div>
            <label htmlFor="email" className="mb-1 block text-sm text-ash-300">
              Email
            </label>
            <input
              id="email"
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="input"
            />
          </div>

          {mode === "register" && (
            <div>
              <label htmlFor="name" className="mb-1 block text-sm text-ash-300">
                Name
              </label>
              <input
                id="name"
                type="text"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="input"
              />
            </div>
          )}

          {mode === "totp" && (
            <div>
              <label htmlFor="code" className="mb-1 block text-sm text-ash-300">
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
                className="input font-mono tracking-[0.3em]"
              />
            </div>
          )}

          {mode === "recovery" && (
            <div>
              <label htmlFor="recoveryCode" className="mb-1 block text-sm text-ash-300">
                Recovery code
              </label>
              <input
                id="recoveryCode"
                type="text"
                placeholder="XXXX-XXXX"
                required
                value={recoveryCode}
                onChange={(e) => setRecoveryCode(e.target.value)}
                className="input font-mono"
              />
            </div>
          )}

          <button type="submit" disabled={busy} className="btn-primary w-full">
            {submitLabels[mode]}
          </button>
        </form>

        {status && <p className="font-mono text-xs text-ash-400">{status}</p>}
        {error && <p className="font-mono text-xs text-rust-400">{error}</p>}

        <div className="ledger-rule flex flex-col gap-2 pt-5 text-sm">
          {mode !== "register" && (
            <button
              type="button"
              onClick={() => {
                setMode("register");
                setError(null);
              }}
              className="link-quiet text-left"
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
              className="link-quiet text-left"
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
              className="link-quiet text-left"
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
              className="link-quiet text-left"
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
