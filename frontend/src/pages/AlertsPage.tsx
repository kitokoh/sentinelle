import { useMemo, useState } from 'react'
import { CheckCheck, RotateCcw, Siren, SlidersHorizontal } from 'lucide-react'
import { getApiErrorMessage } from '../lib/api'
import { ALERTS_REFETCH_MS, useAcknowledgeAlert, useAlertStats, useAlerts } from '../lib/alerts'
import { formatDateTime, formatNumber, formatRelativeTime } from '../lib/format'
import type { Alert } from '../lib/types'
import PageHeader from '../components/PageHeader'
import EmptyState from '../components/EmptyState'
import { ErrorState, LoadingState } from '../components/QueryState'
import { AlertSourceBadge, AlertStatusBadge, ConfidenceBadge, SeverityBadge } from '../components/badges'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const
const SEVERITY_LABELS: Record<string, string> = {
  critical: 'Critique',
  high: 'Élevée',
  medium: 'Moyenne',
  low: 'Faible',
  info: 'Info',
}
const SOURCES = ['suricata', 'rule', 'intel'] as const
const SOURCE_LABELS: Record<string, string> = {
  suricata: 'Suricata (capteur)',
  rule: 'Règle locale',
  intel: 'Renseignement',
}

/** Endpoint affiché dans la colonne « Chemin » ; `—` quand l'alerte est un simple compteur. */
function endpoint(alert: Alert): string {
  const target = alert.dst_ip ? `${alert.dst_ip}${alert.dst_port ? `:${alert.dst_port}` : ''}` : null
  const origin = alert.src_ip ? `${alert.src_ip}${alert.src_port ? `:${alert.src_port}` : ''}` : null
  if (origin && target) return `${origin} → ${target}`
  return target ?? origin ?? '—'
}

function triggerLabel(alert: Alert): string {
  if (alert.rule_name) return alert.rule_name
  if (alert.signature) return alert.signature
  return alert.event_type || '—'
}

export default function AlertsPage() {
  const [severities, setSeverities] = useState<string[]>([])
  const [source, setSource] = useState('')
  const [status, setStatus] = useState('')
  const [pendingId, setPendingId] = useState<number | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)

  const filters = useMemo(
    () => ({
      severity: severities,
      source: source ? [source] : [],
      status: status ? [status] : [],
    }),
    [severities, source, status],
  )

  const statsQuery = useAlertStats()
  const { data, isPending, isError, error, refetch } = useAlerts(filters)
  const acknowledge = useAcknowledgeAlert()

  const stats = statsQuery.data
  const alerts = data ?? []

  function toggleSeverity(value: string) {
    setSeverities((current) =>
      current.includes(value) ? current.filter((item) => item !== value) : [...current, value],
    )
  }

  function setAlertStatus(alert: Alert, next: 'ack' | 'new') {
    setActionError(null)
    setPendingId(alert.id)
    acknowledge.mutate(
      { id: alert.id, status: next },
      {
        onError: (err) => setActionError(getApiErrorMessage(err)),
        onSettled: () => setPendingId(null),
      },
    )
  }

  const hasFilters = severities.length > 0 || source !== '' || status !== ''

  return (
    <div>
      <PageHeader
        title="Alertes"
        description="Détections du capteur Suricata et du moteur de règles local, corrélées dans un flux unique."
      >
        <span className="inline-flex items-center gap-2 text-xs text-slate-500">
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
          Actualisation automatique toutes les {ALERTS_REFETCH_MS / 1000} s
        </span>
      </PageHeader>

      {/* Compteurs */}
      <section className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <div className="panel p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
            Non acquittées
          </p>
          <p className="mt-1 text-2xl font-semibold tabular-nums text-amber-400">
            {formatNumber(stats?.unacknowledged)}
          </p>
        </div>
        <div className="panel p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Total</p>
          <p className="mt-1 text-2xl font-semibold tabular-nums text-slate-200">
            {formatNumber(stats?.total)}
          </p>
        </div>
        <div className="panel p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
            Sévérité élevée
          </p>
          <p className="mt-1 text-2xl font-semibold tabular-nums text-orange-400">
            {formatNumber((stats?.by_severity.critical ?? 0) + (stats?.by_severity.high ?? 0))}
          </p>
        </div>
        <div className="panel p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
            Capteur Suricata
          </p>
          <p className="mt-1 text-2xl font-semibold tabular-nums text-cyan-400">
            {formatNumber(stats?.by_source.suricata)}
          </p>
        </div>
      </section>

      {/* Filtres */}
      <section className="panel mb-6 p-4">
        <div className="flex flex-wrap items-center gap-2">
          <span className="inline-flex items-center gap-2 text-xs font-medium text-slate-400">
            <SlidersHorizontal className="h-3.5 w-3.5" />
            Sévérité
          </span>
          {SEVERITIES.map((value) => {
            const active = severities.includes(value)
            return (
              <button
                key={value}
                type="button"
                onClick={() => toggleSeverity(value)}
                aria-pressed={active}
                className={`rounded-full border px-3 py-1 text-xs transition-colors ${
                  active
                    ? 'border-cyan-400/40 bg-cyan-400/10 text-cyan-400'
                    : 'border-slate-700 bg-slate-800/60 text-slate-400 hover:text-slate-200'
                }`}
              >
                {SEVERITY_LABELS[value]}
              </button>
            )
          })}

          <span className="ml-2 text-xs font-medium text-slate-400">Source</span>
          <select
            className="input max-w-[210px]"
            value={source}
            onChange={(event) => setSource(event.target.value)}
            aria-label="Filtrer par source"
          >
            <option value="">Toutes</option>
            {SOURCES.map((value) => (
              <option key={value} value={value}>
                {SOURCE_LABELS[value]}
              </option>
            ))}
          </select>

          <span className="ml-2 text-xs font-medium text-slate-400">Statut</span>
          <select
            className="input max-w-[190px]"
            value={status}
            onChange={(event) => setStatus(event.target.value)}
            aria-label="Filtrer par statut"
          >
            <option value="">Tous</option>
            <option value="new">Non acquittées</option>
            <option value="ack">Acquittées</option>
          </select>

          {hasFilters ? (
            <button
              type="button"
              className="btn-ghost ml-auto"
              onClick={() => {
                setSeverities([])
                setSource('')
                setStatus('')
              }}
            >
              <RotateCcw className="h-3.5 w-3.5" />
              Réinitialiser
            </button>
          ) : null}
        </div>
      </section>

      {actionError ? (
        <div className="mb-4 rounded-md border border-red-400/30 bg-red-400/10 px-3 py-2.5 text-sm text-red-400">
          {actionError}
        </div>
      ) : null}

      {/* Flux */}
      <section className="panel">
        <div className="border-b border-slate-800 px-5 py-4">
          <h2 className="text-sm font-semibold text-slate-200">
            Flux d'alertes{data ? ` (${data.length})` : ''}
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            Acquitter une alerte enregistre l'auteur et l'horodatage : c'est la première brique du
            journal d'audit.
          </p>
        </div>

        {isPending ? (
          <LoadingState label="Chargement des alertes…" />
        ) : isError ? (
          <ErrorState message={getApiErrorMessage(error)} onRetry={() => refetch()} />
        ) : alerts.length === 0 ? (
          <EmptyState
            icon={Siren}
            title="Aucune alerte"
            description={
              hasFilters
                ? 'Aucune alerte ne correspond à ces filtres.'
                : "Le capteur n'a rien signalé pour l'instant. Lancez un scan sur une cible du lab pour alimenter le flux."
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-800">
                  <th className="th">Sévérité</th>
                  <th className="th">Déclencheur</th>
                  <th className="th">Origine</th>
                  <th className="th">Chemin</th>
                  <th className="th">Confiance</th>
                  <th className="th">Récurrence</th>
                  <th className="th">Statut</th>
                  <th className="th">Quand</th>
                  <th className="th">
                    <span className="sr-only">Action</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr
                    key={alert.id}
                    className={`transition-colors hover:bg-slate-800/40 ${
                      alert.status === 'ack' ? 'opacity-60' : ''
                    }`}
                  >
                    <td className="td">
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td className="td">
                      <p className="font-mono text-xs text-slate-300" title={alert.detail}>
                        {triggerLabel(alert)}
                      </p>
                      <p className="mt-0.5 max-w-[420px] truncate text-xs text-slate-500">
                        {alert.detail}
                      </p>
                    </td>
                    <td className="td">
                      <AlertSourceBadge source={alert.source} />
                    </td>
                    <td className="td font-mono text-xs text-slate-400">{endpoint(alert)}</td>
                    <td className="td">
                      <ConfidenceBadge value={alert.confidence} />
                    </td>
                    <td className="td tabular-nums text-slate-400">×{alert.occurrences}</td>
                    <td className="td">
                      <AlertStatusBadge status={alert.status} />
                    </td>
                    <td className="td">
                      <span title={formatDateTime(alert.created_at)} className="text-slate-400">
                        {formatRelativeTime(alert.created_at)}
                      </span>
                    </td>
                    <td className="td text-right">
                      {alert.status === 'ack' ? (
                        <button
                          type="button"
                          className="btn-ghost"
                          disabled={pendingId === alert.id}
                          onClick={() => setAlertStatus(alert, 'new')}
                          title="Rouvrir l'alerte"
                        >
                          <RotateCcw className="h-3.5 w-3.5" />
                          Rouvrir
                        </button>
                      ) : (
                        <button
                          type="button"
                          className="btn-primary"
                          disabled={pendingId === alert.id}
                          onClick={() => setAlertStatus(alert, 'ack')}
                          title="Acquitter l'alerte"
                        >
                          <CheckCheck className="h-3.5 w-3.5" />
                          {pendingId === alert.id ? 'En cours…' : 'Acquitter'}
                        </button>
                      )}
                    </td>
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
