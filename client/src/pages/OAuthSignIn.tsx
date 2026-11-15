import { useEffect } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../lib/auth.js";
import { authorizeUrl, clearOAuthResume, rememberOAuthResume } from "../lib/oauthResume.js";

// Landing page for an OpenID Connect authorization request that arrived without
// a NovaForge session (see lib/oauthResume.ts). Signed-in users are handed
// straight back to the authorize endpoint; everyone else signs in first.
export default function OAuthSignIn() {
  const { status } = useAuth();
  const search = window.location.search;
  const usable = search.length > 1;

  useEffect(() => {
    if (status === "authenticated" && usable) {
      clearOAuthResume();
      // A full navigation, not a router push: /api/oauth/authorize is a server endpoint.
      window.location.replace(authorizeUrl(search));
    }
  }, [status, usable, search]);

  if (!usable) {
    return (
      <div className="flex min-h-screen items-center justify-center px-6">
        <div className="ledger-card w-full max-w-sm space-y-3 p-8" role="alert">
          <h1 className="font-display text-xl text-parchment-100">Nothing to sign in to</h1>
          <p className="text-sm text-ash-300">This page continues a sign-in started by another application. Return to that application and try again.</p>
        </div>
      </div>
    );
  }

  if (status === "anonymous") {
    // Hold the original request while the normal sign-in runs.
    rememberOAuthResume(search);
    return <Navigate to="/login" replace />;
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-6" role="status" aria-live="polite">
      <p className="font-mono text-sm text-ash-400">Continuing sign-in…</p>
    </div>
  );
}
