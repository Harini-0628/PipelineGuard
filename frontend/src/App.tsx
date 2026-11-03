import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./auth";
import Layout from "./components/Layout";
import { Spinner } from "./components/ui";
import FindingDetail from "./pages/FindingDetail";
import Findings from "./pages/Findings";
import Integrations from "./pages/Integrations";
import Login from "./pages/Login";
import Overview from "./pages/Overview";
import Policies from "./pages/Policies";
import RepositoryDetail from "./pages/RepositoryDetail";
import Repositories from "./pages/Repositories";
import ScanDetail from "./pages/ScanDetail";
import Scans from "./pages/Scans";

export default function App() {
  const { user, loading } = useAuth();
  if (loading) return <Spinner label="Restoring session…" />;
  if (!user) return <Login />;
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Overview />} />
        <Route path="repositories" element={<Repositories />} />
        <Route path="repositories/:id" element={<RepositoryDetail />} />
        <Route path="scans" element={<Scans />} />
        <Route path="scans/:id" element={<ScanDetail />} />
        <Route path="findings" element={<Findings />} />
        <Route path="findings/:id" element={<FindingDetail />} />
        <Route path="policies" element={<Policies />} />
        <Route path="settings" element={<Integrations />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
