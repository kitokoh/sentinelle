import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { Loader2, ShieldAlert } from 'lucide-react'
import { TOKEN_KEY } from '../lib/api'

/**
 * Retour du fournisseur d'identité (SSO/OIDC).
 *
 * Le jeton arrive dans le **fragment** d'URL (`#token=…`) : les fragments ne sont
 * pas transmis au serveur, il n'apparaît donc pas dans les journaux du reverse
 * proxy. Il est stocké puis effacé de l'URL par un rechargement complet, pour que
 * le contexte d'authentification reparte d'un état propre.
 */
export default function AuthCallbackPage() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const params = new URLSearchParams(window.location.hash.replace(/^#/, ''))
    const token = params.get('token')

    if (token) {
      localStorage.setItem(TOKEN_KEY, token)
      queryClient.clear()
      window.location.replace('/')
      return
    }

    setError("Le fournisseur d'identité n'a pas renvoyé de jeton exploitable.")
    const timeout = window.setTimeout(() => navigate('/login', { replace: true }), 2500)
    return () => window.clearTimeout(timeout)
  }, [navigate, queryClient])

  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-3 bg-slate-950 px-4">
      {error ? (
        <>
          <ShieldAlert className="h-6 w-6 text-amber-400" />
          <p className="max-w-md text-center text-sm text-slate-400">{error}</p>
          <p className="text-xs text-slate-600">Retour à la page de connexion…</p>
        </>
      ) : (
        <>
          <Loader2 className="h-6 w-6 animate-spin text-cyan-400" />
          <p className="text-sm text-slate-400">Authentification en cours…</p>
        </>
      )}
    </div>
  )
}
