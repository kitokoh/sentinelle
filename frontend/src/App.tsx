import { Navigate, Route, Routes } from 'react-router-dom'
import ProtectedRoute from './components/ProtectedRoute'
import Layout from './components/Layout'
import LoginPage from './pages/LoginPage'
import AuthCallbackPage from './pages/AuthCallbackPage'
import DashboardPage from './pages/DashboardPage'
import TargetsPage from './pages/TargetsPage'
import ScansPage from './pages/ScansPage'
import ScanDetailPage from './pages/ScanDetailPage'
import AlertsPage from './pages/AlertsPage'
import IntelPage from './pages/IntelPage'
import AuditPage from './pages/AuditPage'
import ReportsPage from './pages/ReportsPage'
import DoctrinePage from './pages/DoctrinePage'

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      {/* Retour du fournisseur d'identité : route publique, le jeton arrive en fragment. */}
      <Route path="/auth/callback" element={<AuthCallbackPage />} />

      <Route element={<ProtectedRoute />}>
        <Route element={<Layout />}>
          <Route index element={<DashboardPage />} />
          <Route path="cibles" element={<TargetsPage />} />
          <Route path="scans" element={<ScansPage />} />
          <Route path="scans/:id" element={<ScanDetailPage />} />
          <Route path="alertes" element={<AlertsPage />} />
          <Route path="renseignement" element={<IntelPage />} />
          <Route path="rapports" element={<ReportsPage />} />
          <Route path="journal" element={<AuditPage />} />
          <Route path="doctrine" element={<DoctrinePage />} />
        </Route>
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
