import { useState, type FormEvent } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, KeyRound, Loader2, Lock, Mail, Shield } from 'lucide-react'
import { api, getApiErrorMessage } from '../lib/api'
import { useAuth } from '../auth/AuthContext'

interface OidcConfig {
  enabled: boolean
  provider: string | null
  login_url: string | null
}

/** Message d'erreur éventuellement renvoyé par le fournisseur d'identité. */
function ssoErrorFromUrl(): string | null {
  const params = new URLSearchParams(window.location.hash.replace(/^#/, ''))
  const code = params.get('sso_error')
  if (!code) return null
  if (code === 'invalid_state') return "Session SSO expirée ou invalide — réessayez."
  if (code === 'exchange_failed') return "Le fournisseur d'identité a refusé la connexion."
  if (code === 'access_denied') return 'Connexion annulée auprès du fournisseur.'
  return `Échec de la connexion SSO (${code}).`
}

type Mode = 'login' | 'register'

export default function LoginPage() {
  const { token, login, register } = useAuth()
  const navigate = useNavigate()

  const [mode, setMode] = useState<Mode>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(ssoErrorFromUrl)
  const [isSubmitting, setIsSubmitting] = useState(false)

  // Le bouton SSO n'apparaît que si l'instance est configurée côté API.
  const { data: oidc } = useQuery({
    queryKey: ['oidc', 'config'],
    queryFn: async (): Promise<OidcConfig> => {
      const { data } = await api.get<OidcConfig>('/auth/oidc/config')
      return data
    },
    staleTime: 5 * 60_000,
  })

  // Déjà authentifié : retour direct au poste de commandement.
  if (token) {
    return <Navigate to="/" replace />
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError(null)
    setIsSubmitting(true)
    try {
      if (mode === 'login') {
        await login(email, password)
      } else {
        await register(email, password)
      }
      navigate('/', { replace: true })
    } catch (err) {
      setError(getApiErrorMessage(err))
    } finally {
      setIsSubmitting(false)
    }
  }

  function switchMode(next: Mode) {
    setMode(next)
    setError(null)
  }

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-slate-950 px-4">
      <div className="w-full max-w-md">
        {/* Marque */}
        <div className="mb-8 flex flex-col items-center">
          <div className="rounded-lg border border-cyan-400/30 p-3 text-cyan-400">
            <Shield className="h-8 w-8" />
          </div>
          <h1 className="mt-4 text-2xl font-bold tracking-[0.25em] text-slate-100">SENTINELLE</h1>
          <p className="mt-1 text-sm text-slate-500">
            Plateforme souveraine d'audit de sécurité
          </p>
        </div>

        {/* Carte de connexion */}
        <div className="panel p-6">
          {/* Bascule connexion / inscription */}
          <div className="mb-6 grid grid-cols-2 gap-1 rounded-md border border-slate-800 bg-slate-950 p-1">
            {(
              [
                { key: 'login', label: 'Connexion' },
                { key: 'register', label: 'Inscription' },
              ] as const
            ).map(({ key, label }) => (
              <button
                key={key}
                type="button"
                onClick={() => switchMode(key)}
                className={`rounded px-3 py-1.5 text-sm font-medium transition-colors ${
                  mode === key
                    ? 'bg-slate-800 text-cyan-400'
                    : 'text-slate-500 hover:text-slate-300'
                }`}
              >
                {label}
              </button>
            ))}
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="email" className="label">
                Adresse e-mail
              </label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-600" />
                <input
                  id="email"
                  type="email"
                  required
                  autoComplete="email"
                  className="input pl-9"
                  placeholder="operateur@exemple.gouv.fr"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
              </div>
            </div>

            <div>
              <label htmlFor="password" className="label">
                Mot de passe
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-600" />
                <input
                  id="password"
                  type="password"
                  required
                  minLength={8}
                  autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                  className="input pl-9"
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </div>
              {mode === 'register' ? (
                <p className="helper">8 caractères minimum.</p>
              ) : null}
            </div>

            {error ? (
              <div className="flex items-start gap-2 rounded-md border border-red-400/30 bg-red-400/10 px-3 py-2.5 text-sm text-red-400">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{error}</span>
              </div>
            ) : null}

            <button type="submit" className="btn-primary w-full" disabled={isSubmitting}>
              {isSubmitting ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
              {mode === 'login' ? 'Se connecter' : "Créer le compte"}
            </button>

            {oidc?.enabled && oidc.login_url ? (
              <>
                <div className="flex items-center gap-3">
                  <span className="h-px flex-1 bg-slate-800" />
                  <span className="text-[10px] uppercase tracking-wider text-slate-600">ou</span>
                  <span className="h-px flex-1 bg-slate-800" />
                </div>
                <a href={oidc.login_url} className="btn-ghost w-full justify-center">
                  <KeyRound className="h-4 w-4" />
                  Se connecter avec {oidc.provider ?? 'le SSO'}
                </a>
                <p className="helper">
                  Authentification déléguée au fournisseur d'identité de votre organisation.
                </p>
              </>
            ) : null}
          </form>
        </div>

        <p className="mt-6 text-center text-xs text-slate-600">
          Accès réservé au personnel autorisé — Sentinelle v0.5 · diffusion restreinte
        </p>
      </div>
    </div>
  )
}
