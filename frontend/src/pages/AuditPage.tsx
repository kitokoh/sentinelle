import { useState } from 'react'
import { History, RotateCcw, ShieldAlert } from 'lucide-react'
import { getApiErrorMessage } from '../lib/api'
import { useAuditActions, useAuditLog } from '../lib/audit'
import { formatDateTime, formatRelativeTime } from '../lib/format'
import { useAuth } from '../auth/AuthContext'
import PageHeader from '../components/PageHeader'
import EmptyState from '../components/EmptyState'
import { ErrorState, LoadingState } from '../components/QueryState'

/** Une couleur par famille d'action, pour lire le journal d'un coup d'œil. */
function actionTone(action: string): string {
  if (action.startsWith('auth.')) return 'border-cyan-400/30 bg-cyan-400/10 text-cyan-300'
  if (action.endsWith('.create')) return 'border-emerald-400/30 bg-emerald-400/10 text-emerald-400'
  if (action.endsWith('.delete')) return 'border-red-400/30 bg-red-400/10 text-red-400'
  if (action.startsWith('users.')) return 'border-violet-400/30 bg-violet-400/10 text-violet-300'
  return 'border-slate-700 bg-slate-800 text-slate-400'
}

function statusTone(code: number): string {
  if (code < 300) return 'text-emerald-400'
  if (code < 400) return 'text-slate-400'
  if (code === 401 || code === 403) return 'text-amber-400'
  return 'text-red-400'
}

export default function AuditPage() {
  const { user } = useAuth()
  const [actor, setActor] = useState('')
  const [action, setAction] = useState('')
  const [entity, setEntity] = useState('')

  const actions = useAuditActions()
  const { data, isPending, isError, error, refetch } = useAuditLog({ actor, action, entity })

  const isAdmin = user?.role === 'admin'
  const hasFilters = actor !== '' || action !== '' || entity !== ''

  return (
    <div>
      <PageHeader
        title="Journal d'audit"
        description="Qui a fait quoi, quand — écrit automatiquement à chaque modification, en lecture seule."
      />

      {!isAdmin ? (
        <div className="panel mb-6 flex items-start gap-3 border-amber-400/30 p-4">
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
          <div>
            <p className="text-sm text-amber-300">Accès réservé aux administrateurs</p>
            <p className="mt-1 text-xs text-slate-500">
              Votre rôle ({user?.role ?? 'inconnu'}) ne permet pas de consulter le journal. La
              restriction est appliquée par l'API, pas seulement par cette page.
            </p>
          </div>
        </div>
      ) : null}

      <section className="panel mb-6 p-4">
        <div className="flex flex-wrap items-end gap-3">
          <div>
            <label htmlFor="audit-actor" className="label">
              Acteur
            </label>
            <input
              id="audit-actor"
              className="input max-w-[240px]"
              placeholder="adresse e-mail…"
              value={actor}
              onChange={(event) => setActor(event.target.value)}
            />
          </div>

          <div>
            <label htmlFor="audit-action" className="label">
              Action
            </label>
            <select
              id="audit-action"
              className="input max-w-[240px]"
              value={action}
              onChange={(event) => setAction(event.target.value)}
            >
              <option value="">Toutes</option>
              {(actions.data ?? []).map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label htmlFor="audit-entity" className="label">
              Entité
            </label>
            <input
              id="audit-entity"
              className="input max-w-[180px]"
              placeholder="targets, scans, users…"
              value={entity}
              onChange={(event) => setEntity(event.target.value)}
            />
          </div>

          {hasFilters ? (
            <button
              type="button"
              className="btn-ghost ml-auto"
              onClick={() => {
                setActor('')
                setAction('')
                setEntity('')
              }}
            >
              <RotateCcw className="h-3.5 w-3.5" />
              Réinitialiser
            </button>
          ) : null}
        </div>
      </section>

      <section className="panel">
        <div className="border-b border-slate-800 px-5 py-4">
          <h2 className="text-sm font-semibold text-slate-200">
            Événements{data ? ` (${data.length})` : ''}
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            Aucun corps de requête n'est conservé : les mots de passe et les jetons ne figurent
            jamais dans le journal. Les lectures (GET) ne sont pas tracées.
          </p>
        </div>

        {isPending ? (
          <LoadingState label="Chargement du journal…" />
        ) : isError ? (
          <ErrorState message={getApiErrorMessage(error)} onRetry={() => refetch()} />
        ) : (data ?? []).length === 0 ? (
          <EmptyState
            icon={History}
            title="Aucun événement"
            description={
              hasFilters
                ? 'Aucun événement ne correspond à ces filtres.'
                : 'Aucune action modifiant l’état n’a encore été enregistrée.'
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-800">
                  <th className="th">Quand</th>
                  <th className="th">Acteur</th>
                  <th className="th">Action</th>
                  <th className="th">Ressource</th>
                  <th className="th">Statut</th>
                  <th className="th">Origine</th>
                </tr>
              </thead>
              <tbody>
                {(data ?? []).map((row) => (
                  <tr key={row.id} className="transition-colors hover:bg-slate-800/40">
                    <td className="td">
                      <span title={formatDateTime(row.created_at)} className="text-slate-300">
                        {formatRelativeTime(row.created_at)}
                      </span>
                    </td>
                    <td className="td text-slate-300">
                      {row.actor_email ?? <span className="text-slate-600">anonyme</span>}
                    </td>
                    <td className="td">
                      <span
                        className={`inline-flex items-center rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${actionTone(row.action)}`}
                      >
                        {row.action}
                      </span>
                      {row.detail ? (
                        <p className="mt-1 max-w-[320px] truncate text-xs text-slate-500" title={row.detail}>
                          {row.detail}
                        </p>
                      ) : null}
                    </td>
                    <td className="td font-mono text-xs text-slate-500">
                      {row.entity ?? '—'}
                      {row.entity_id !== null ? `#${row.entity_id}` : ''}
                    </td>
                    <td className={`td font-mono text-xs ${statusTone(row.status_code)}`}>
                      {row.status_code}
                    </td>
                    <td className="td font-mono text-xs text-slate-500">{row.ip ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}
