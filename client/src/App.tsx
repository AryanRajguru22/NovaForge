import { Route, Routes, Link } from "react-router-dom";
import Login from "./pages/Login.js";
import Settings from "./pages/Settings.js";
import ApprovalDashboard from "./pages/ApprovalDashboard.js";
import PolicyManagement from "./pages/PolicyManagement.js";

function Home() {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center gap-4 bg-slate-950 text-slate-100">
      <h1 className="text-3xl font-semibold">NovaForge</h1>
      <p className="text-slate-400">Passwordless auth + approval-policy platform</p>
      <nav className="flex gap-4 text-sm text-slate-300">
        <Link to="/login" className="hover:text-white">
          Login
        </Link>
        <Link to="/approvals" className="hover:text-white">
          Approvals
        </Link>
        <Link to="/settings" className="hover:text-white">
          Security settings
        </Link>
      </nav>
    </div>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/login" element={<Login />} />
      <Route path="/approvals" element={<ApprovalDashboard />} />
      <Route path="/policies" element={<PolicyManagement />} />
      <Route path="/settings" element={<Settings />} />
    </Routes>
  );
}
