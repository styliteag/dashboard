import { Routes, Route, Navigate } from "react-router-dom";
import ProtectedRoute from "./components/ProtectedRoute";
import Layout from "./components/Layout";
import LoginPage from "./pages/LoginPage";
import InstancesPage from "./pages/InstancesPage";
import InstanceDetailPage from "./pages/InstanceDetailPage";
import VPNOverviewPage from "./pages/VPNOverviewPage";
import FirmwareCompliancePage from "./pages/FirmwareCompliancePage";
import AuditPage from "./pages/AuditPage";
import PasswordPage from "./pages/PasswordPage";

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />

      <Route element={<ProtectedRoute />}>
        <Route element={<Layout />}>
          <Route index element={<InstancesPage />} />
          <Route path="instances/:id" element={<InstanceDetailPage />} />
          <Route path="vpn" element={<VPNOverviewPage />} />
          <Route path="firmware" element={<FirmwareCompliancePage />} />
          <Route path="audit" element={<AuditPage />} />
          <Route path="password" element={<PasswordPage />} />
        </Route>
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
