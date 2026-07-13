import { Link, Outlet, useNavigate } from "react-router-dom";
import {
  Activity,
  LogOut,
  Server,
  Shield,
  KeyRound,
  FileText,
  Package,
  BadgeCheck,
  Settings,
  AlertTriangle,
  FolderTree,
  Radio,
  ScrollText,
  Users,
  ShieldCheck,
  Globe2,
} from "lucide-react";
import { useAuth } from "../lib/use-auth";
import VersionFooter from "./VersionFooter";

export default function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate("/login");
  };

  return (
    <div className="flex min-h-screen flex-col bg-slate-950 text-slate-100">
      <header className="sticky top-0 z-50 flex items-center justify-between border-b border-slate-800 bg-slate-950/80 px-6 py-3 backdrop-blur">
        <Link
          to="/"
          className="flex items-center gap-2 text-lg font-semibold tracking-tight hover:text-slate-300"
        >
          <Shield className="h-5 w-5 text-emerald-500" />
          Orbit Dashboard
        </Link>

        <nav className="flex items-center gap-4 text-sm">
          {user?.is_admin && (
            <Link
              to="/hub"
              className="flex items-center gap-1.5 text-slate-400 hover:text-slate-100"
            >
              <Activity className="h-4 w-4" /> Hub
            </Link>
          )}
          <Link
            to="/instances"
            className="flex items-center gap-1.5 text-slate-400 hover:text-slate-100"
          >
            <Server className="h-4 w-4" /> Instances
          </Link>
          <Link to="/vpn" className="flex items-center gap-1.5 text-slate-400 hover:text-slate-100">
            <Shield className="h-4 w-4" /> VPN
          </Link>
          <Link
            to="/connectivity"
            className="flex items-center gap-1.5 text-slate-400 hover:text-slate-100"
          >
            <Radio className="h-4 w-4" /> Connectivity
          </Link>
          <Link
            to="/firmware"
            className="flex items-center gap-1.5 text-slate-400 hover:text-slate-100"
          >
            <Package className="h-4 w-4" /> Firmware
          </Link>
          <Link
            to="/certs"
            className="flex items-center gap-1.5 text-slate-400 hover:text-slate-100"
          >
            <BadgeCheck className="h-4 w-4" /> Certs
          </Link>
          <Link
            to="/alerts"
            className="flex items-center gap-1.5 text-slate-400 hover:text-slate-100"
          >
            <AlertTriangle className="h-4 w-4" /> Alerts
          </Link>
          <Link
            to="/logs"
            className="flex items-center gap-1.5 text-slate-400 hover:text-slate-100"
          >
            <ScrollText className="h-4 w-4" /> Logs
          </Link>
          {(user?.is_admin || user?.is_superadmin) && (
            <Link
              to="/audit"
              className="flex items-center gap-1.5 text-slate-400 hover:text-slate-100"
            >
              <FileText className="h-4 w-4" /> Audit
            </Link>
          )}
          <Link
            to="/password"
            className="flex items-center gap-1.5 text-slate-400 hover:text-slate-100"
          >
            <KeyRound className="h-4 w-4" /> Password
          </Link>
          <Link
            to="/security"
            className="flex items-center gap-1.5 text-slate-400 hover:text-slate-100"
          >
            <ShieldCheck className="h-4 w-4" /> Security
          </Link>
          {user?.is_admin && (
            <Link
              to="/settings"
              className="flex items-center gap-1.5 text-slate-400 hover:text-slate-100"
            >
              <Settings className="h-4 w-4" /> Settings
            </Link>
          )}
          {user?.is_superadmin && (
            <Link
              to="/users"
              className="flex items-center gap-1.5 text-slate-400 hover:text-slate-100"
            >
              <Users className="h-4 w-4" /> Users
            </Link>
          )}
          {user?.is_superadmin && (
            <Link
              to="/groups"
              className="flex items-center gap-1.5 text-slate-400 hover:text-slate-100"
            >
              <FolderTree className="h-4 w-4" /> Groups
            </Link>
          )}
          {user?.is_superadmin && (
            <Link
              to="/access"
              className="flex items-center gap-1.5 text-slate-400 hover:text-slate-100"
            >
              <Globe2 className="h-4 w-4" /> Access
            </Link>
          )}
          <span className="text-slate-600">|</span>
          <span className="text-slate-500">
            {user?.username}
            {user && (
              <span className="ml-1 rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-400">
                {user.is_superadmin
                  ? "superadmin"
                  : user.role === "view_only"
                    ? "view-only"
                    : user.role}
              </span>
            )}
          </span>
          <button
            onClick={handleLogout}
            className="flex items-center gap-1 text-slate-400 hover:text-red-400"
          >
            <LogOut className="h-4 w-4" />
          </button>
        </nav>
      </header>

      <main className="w-full flex-1 px-6 py-8">
        <Outlet />
      </main>

      <VersionFooter />
    </div>
  );
}
