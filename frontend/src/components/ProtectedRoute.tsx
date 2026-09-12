import { Navigate, Outlet } from 'react-router-dom'
import { Loader2, Shield } from 'lucide-react'
import { useAuth } from '../auth/AuthContext'

/** Garde d'authentification : redirige vers /login sans session, sinon laisse passer. */
export default function ProtectedRoute() {
  const { token, isLoading } = useAuth()

  if (!token) {
    return <Navigate to="/login" replace />
  }

  if (isLoading) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-slate-950">
        <Shield className="h-8 w-8 text-cyan-400" />
        <p className="flex items-center gap-2 text-sm text-slate-500">
          <Loader2 className="h-4 w-4 animate-spin" />
          Vérification de la session…
        </p>
      </div>
    )
  }

  return <Outlet />
}
