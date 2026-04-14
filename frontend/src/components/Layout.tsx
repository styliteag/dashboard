import { Link, Outlet, useNavigate } from "react-router-dom";
import { LogOut, Server, Shield, KeyRound, FileText, Package } from "lucide-react";
import { useAuth } from "../lib/auth-context";

export default function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate("/login");
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="sticky top-0 z-50 flex items-center justify-between border-b border-slate-800 bg-slate-950/80 px-6 py-3 backdrop-blur">
        <Link
          to="/"
          className="flex items-center gap-2 text-lg font-semibold tracking-tight hover:text-slate-300"
        >
          <Shield className="h-5 w-5 text-emerald-500" />
          opnsense-dash
        </Link>

        <nav className="flex items-center gap-4 text-sm">
          <Link to="/" className="flex items-center gap-1.5 text-slate-400 hover:text-slate-100">
            <Server className="h-4 w-4" /> Instances
          </Link>
          <Link to="/vpn" className="flex items-center gap-1.5 text-slate-400 hover:text-slate-100">
            <Shield className="h-4 w-4" /> VPN
          </Link>
          <Link to="/firmware" className="flex items-center gap-1.5 text-slate-400 hover:text-slate-100">
            <Package className="h-4 w-4" /> Firmware
          </Link>
          <Link to="/audit" className="flex items-center gap-1.5 text-slate-400 hover:text-slate-100">
            <FileText className="h-4 w-4" /> Audit
          </Link>
          <Link to="/password" className="flex items-center gap-1.5 text-slate-400 hover:text-slate-100">
            <KeyRound className="h-4 w-4" /> Password
          </Link>
          <span className="text-slate-600">|</span>
          <span className="text-slate-500">{user?.username}</span>
          <button
            onClick={handleLogout}
            className="flex items-center gap-1 text-slate-400 hover:text-red-400"
          >
            <LogOut className="h-4 w-4" />
          </button>
        </nav>
      </header>

      <main className="mx-auto max-w-7xl px-6 py-8">
        <Outlet />
      </main>
    </div>
  );
}
