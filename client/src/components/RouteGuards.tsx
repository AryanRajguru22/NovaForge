import { Navigate, Outlet } from "react-router-dom";
import { useAuth } from "../lib/auth.js";

function Checking() {
  return <div className="font-mono p-8 text-sm text-ash-400">Loading…</div>;
}

// Gates the authenticated app -- anyone without a session bounces to /login.
// Uses `replace` so /login never sits in front of the protected page in
// history, which is what let the browser Back button land on the login form
// after a valid, successful sign-in.
export function ProtectedRoute() {
  const { status } = useAuth();
  if (status === "loading") return <Checking />;
  if (status === "anonymous") return <Navigate to="/login" replace />;
  return <Outlet />;
}

// Mirror of ProtectedRoute for /login itself -- an already-authenticated user
// who ends up back on /login (e.g. via Back) gets bounced forward instead of
// being shown the sign-in form again.
export function PublicOnlyRoute() {
  const { status } = useAuth();
  if (status === "loading") return <Checking />;
  if (status === "authenticated") return <Navigate to="/approvals" replace />;
  return <Outlet />;
}
