import { useEffect, lazy, Suspense } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import useAuthStore from './store/auth';
import RequireAuth from './routes/RequireAuth';
import RequireRole from './routes/RequireRole';
import AppShell from './layout/AppShell';
// Login stays eager — it is the entry point and part of the first paint.
import Login from './pages/Login';

// Route-level code-splitting: each page becomes its own chunk so the cytoscape-heavy
// Pivot/Topology pages (and everything else) load on demand instead of bloating the
// main bundle. Routing is unchanged.
const Dashboard = lazy(() => import('./pages/Dashboard'));
const Scenarios = lazy(() => import('./pages/Scenarios'));
const UsersPage = lazy(() => import('./pages/Users'));
const Topology = lazy(() => import('./pages/Topology'));
const HostRisk = lazy(() => import('./pages/HostRisk'));
const CoverageGaps = lazy(() => import('./pages/CoverageGaps'));
const AttackPaths = lazy(() => import('./pages/AttackPaths'));
const Intel = lazy(() => import('./pages/Intel'));
const Timeline = lazy(() => import('./pages/Timeline'));
const Pivot = lazy(() => import('./pages/Pivot'));
const Campaign = lazy(() => import('./pages/Campaign'));
const Handover = lazy(() => import('./pages/Handover'));
const Drill = lazy(() => import('./pages/Drill'));
const Account = lazy(() => import('./pages/Account'));
const Sessions = lazy(() => import('./pages/Sessions'));
const Audit = lazy(() => import('./pages/Audit'));
const Candidates = lazy(() => import('./pages/Candidates'));
const Alerts = lazy(() => import('./pages/Alerts'));
const Hunts = lazy(() => import('./pages/Hunts'));
const Stack = lazy(() => import('./pages/Stack'));
const Tuning = lazy(() => import('./pages/Tuning'));
const DetectionHealth = lazy(() => import('./pages/DetectionHealth'));
const Incidents = lazy(() => import('./pages/Incidents'));

function AuthBootstrap({ children }: { children: React.ReactNode }) {
  const bootstrap = useAuthStore((s) => s.bootstrap);
  const status = useAuthStore((s) => s.status);

  useEffect(() => {
    if (status === 'loading') {
      void bootstrap();
    }
  }, [bootstrap, status]);

  return <>{children}</>;
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthBootstrap>
        <Suspense fallback={<div className="p-6 text-sm" style={{ color: 'var(--muted)' }} />}>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            element={
              <RequireAuth>
                <AppShell />
              </RequireAuth>
            }
          >
            <Route index element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/scenarios" element={<Scenarios />} />
            <Route path="/topology" element={<Topology />} />
            <Route path="/host-risk" element={<HostRisk />} />
            <Route path="/coverage-gaps" element={<CoverageGaps />} />
            <Route path="/attack-paths" element={<AttackPaths />} />
            <Route path="/intel" element={<Intel />} />
            <Route path="/timeline" element={<Timeline />} />
            <Route path="/pivot" element={<Pivot />} />
            <Route path="/campaign" element={<Campaign />} />
            <Route path="/handover" element={<Handover />} />
            <Route path="/account" element={<Account />} />
            <Route path="/sessions" element={<Sessions />} />
            <Route
              path="/candidates"
              element={
                <RequireRole role="analyst">
                  <Candidates />
                </RequireRole>
              }
            />
            <Route path="/alerts" element={<RequireRole role="analyst"><Alerts /></RequireRole>} />
            <Route path="/drill" element={<RequireRole role="analyst"><Drill /></RequireRole>} />
            <Route path="/hunts" element={<Hunts />} />
            <Route path="/stack" element={<Stack />} />
            <Route path="/tuning" element={<Tuning />} />
            <Route path="/health" element={<DetectionHealth />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route
              path="/users"
              element={
                <RequireRole role="admin">
                  <UsersPage />
                </RequireRole>
              }
            />
            <Route
              path="/audit"
              element={
                <RequireRole role="admin">
                  <Audit />
                </RequireRole>
              }
            />
          </Route>
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
        </Suspense>
      </AuthBootstrap>
    </BrowserRouter>
  );
}
