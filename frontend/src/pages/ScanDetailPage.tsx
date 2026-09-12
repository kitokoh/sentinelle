import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ArrowLeft, Bug, ShieldCheck } from 'lucide-react'
import { api, getApiErrorMessage } from '../lib/api'
import { formatDateTime, PROFILE_LABELS } from '../lib/format'
import type { ScanDetail } from '../lib/types'
import PageHeader from '../components/PageHeader'
import EmptyState from '../components/EmptyState'
import { ErrorState, LoadingState } from '../components/QueryState'
import { SeverityBadge, StatusBadge } from '../components/badges'

async function fetchScan(id: string): Promise<ScanDetail> {
  const { data } = await api.get<ScanDetail>(`/scans/${id}`)
  return data
}

export default function ScanDetailPage() {
  const { id = '' } = useParams<{ id: string }>()

  const { data, isPending, isError, error, refetch } = useQuery({
    queryKey: ['scans', id],
    queryFn: () => fetchScan(id),
    enabled: id !== '',
    // Tant que le scan est actif, on rafraîchit pour suivre l'avancement.
    refetchInterval: (query) => {
      const status = query.state.data?.status
      return status === 'pending' || status === 'running' ? 3_000 : false
    },
  })

  return (
    <div>
      <div className="mb-4">
        <Link to="/scans" className="btn-ghost text-xs">
          <ArrowLeft className="h-3.5 w-3.5" />
          Retour aux scans
        </Link>
      </div>

      <PageHeader
        title={`Scan #${id}`}
        description="Détail de la campagne et constats remontés par la reconnaissance."
      />

      {isPending ? (
        <div className="panel">
          <LoadingState />
        </div>
      ) : isError ? (
        <div className="panel">
          <ErrorState message={getApiErrorMessage(error)} onRetry={() => refetch()} />
        </div>
      ) : (
        <>
          {/* Métadonnées */}
          <section className="panel mb-6 p-5">
            <dl className="grid grid-cols-2 gap-x-6 gap-y-5 md:grid-cols-3 xl:grid-cols-6">
              <div>
                <dt className="label mb-1">Cible</dt>
                <dd className="text-sm font-medium text-slate-200">
                  {data.target?.name ?? `Cible #${data.target_id}`}
                </dd>
                {data.target ? (
                  <dd className="mt-0.5 font-mono text-xs text-slate-500">{data.target.value}</dd>
                ) : null}
              </div>
              <div>
                <dt className="label mb-1">Profil</dt>
                <dd className="text-sm text-slate-300">
                  {PROFILE_LABELS[data.profile] ?? data.profile}
                </dd>
              </div>
              <div>
                <dt className="label mb-1">Statut</dt>
                <dd>
                  <StatusBadge status={data.status} />
                </dd>
              </div>
              <div>
                <dt className="label mb-1">Lancé le</dt>
                <dd className="text-sm text-slate-300">{formatDateTime(data.created_at)}</dd>
              </div>
              <div>
                <dt className="label mb-1">Terminé le</dt>
                <dd className="text-sm text-slate-300">{formatDateTime(data.finished_at)}</dd>
              </div>
              <div>
                <dt className="label mb-1">Constats</dt>
                <dd className="text-sm font-semibold tabular-nums text-slate-200">
                  {data.findings.length}
                </dd>
              </div>
            </dl>
          </section>

          {/* Constats */}
          <section className="panel">
            <div className="border-b border-slate-800 px-5 py-4">
              <h2 className="text-sm font-semibold text-slate-200">
                Constats ({data.findings.length})
              </h2>
              <p className="mt-1 text-xs text-slate-500">
                Ports ouverts, services exposés et sévérité associée.
              </p>
            </div>

            {data.findings.length === 0 ? (
              <EmptyState
                icon={data.status === 'done' ? ShieldCheck : Bug}
                title={
                  data.status === 'done'
                    ? 'Aucun constat — surface exposée conforme'
                    : 'Aucun constat remonté pour le moment'
                }
                description={
                  data.status === 'pending' || data.status === 'running'
                    ? "L'analyse est en cours, les résultats apparaîtront automatiquement."
                    : undefined
                }
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-slate-800">
                      <th className="th">Port</th>
                      <th className="th">Proto</th>
                      <th className="th">Service</th>
                      <th className="th">Version</th>
                      <th className="th">Sévérité</th>
                      <th className="th">Détail</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.findings.map((finding) => (
                      <tr key={finding.id} className="transition-colors hover:bg-slate-800/40">
                        <td className="td font-mono text-xs font-semibold text-slate-200">
                          {finding.port}
                        </td>
                        <td className="td font-mono text-xs uppercase text-slate-400">
                          {finding.protocol}
                        </td>
                        <td className="td font-medium text-slate-200">{finding.service}</td>
                        <td className="td font-mono text-xs text-slate-400">
                          {finding.version ?? '—'}
                        </td>
                        <td className="td">
                          <SeverityBadge severity={finding.severity} />
                        </td>
                        <td className="td max-w-md text-xs leading-relaxed text-slate-400">
                          {finding.detail ?? '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </>
      )}
    </div>
  )
}
