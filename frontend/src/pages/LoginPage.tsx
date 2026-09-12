import { useState, type FormEvent } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import { AlertTriangle, Loader2, Lock, Mail, Shield } from 'lucide-react'
import { useAuth } from '../auth/AuthContext'
import { getApiErrorMessage } from '../lib/api'

type Mode = 'login' | 'register'

export default function LoginPage() {
  const { token, login, register } = useAuth()
  const navigate = useNavigate()

  const [mode, setMode] = useState<Mode>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)

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
          </form>
        </div>

        <p className="mt-6 text-center text-xs text-slate-600">
          Accès réservé au personnel autorisé — Sentinelle v0.4 · diffusion restreinte
        </p>
      </div>
    </div>
  )
}
