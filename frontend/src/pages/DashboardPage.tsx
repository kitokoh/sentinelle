import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, Bug, ChevronRight, Crosshair, Radar } from 'lucide-react'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { api, getApiErrorMessage } from '../lib/api'
import { formatDateTime, formatNumber, PROFILE_LABELS } from '../lib/format'
import type { DashboardStats } from '../lib/types'
import PageHeader from '../components/PageHeader'
import StatCard from '../components/StatCard'
import { StatusBadge } from '../components/badges'
import EmptyState from '../components/EmptyState'
import { ErrorState, LoadingState } from '../components/QueryState'

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const

const SEVERITY_LABELS: Record<string, string> = {
  critical: 'Critique',
  high: 'Élevée',
  medium: 'Moyenne',
  low: 'Faible',
  info: 'Info',
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#fb923c',
  medium: '#fbbf24',
  low: '#22d3ee',
  info: '#94a3b8',
}

async function fetchStats(): Promise<DashboardStats> {
  const { data } = await api.get<DashboardStats>('/dashboard/stats')
  return data
}

export default function DashboardPage() {
  const { data, isPending, isError, error, refetch } = useQuery({
    queryKey: ['dashboard', 'stats'],
    queryFn: fetchStats,
    refetchInterval: 5_000,
  })

  const chartData = SEVERITY_ORDER.map((severity) => ({
    severity: SEVERITY_LABELS[severity],
    count: data?.findings_by_severity?.[severity] ?? 0,
    fill: SEVERITY_COLORS[severity],
  }))

  return (
    <div>
      <PageHeader
        title="Tableau de bord"
        description="Vue d'ensemble de l'activité de la plateforme — actualisation automatique."
      />

      {isPending ? (
        <div className="panel">
          <LoadingState label="Synchronisation avec le SOC…" />
        </div>
      ) : isError ? (
        <div className="panel">
          <ErrorState message={getApiErrorMessage(error)} onRetry={() => refetch()} />
        </div>
      ) : (
        <>
          {/* Cartes de synthèse */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard
              label="Cibles"
              value={formatNumber(data.targets)}
              icon={Crosshair}
              tone="cyan"
              hint="Actifs déclarés au registre"
            />
            <StatCard
              label="Scans"
              value={formatNumber(data.scans)}
              icon={Radar}
              tone="cyan"
              hint="Campagnes exécutées"
            />
            <StatCard
              label="Constats"
              value={formatNumber(data.findings)}
              icon={Bug}
              tone="emerald"
              hint="Toutes sévérités confondues"
            />
            <StatCard
              label="Critiques"
              value={formatNumber(data.findings_by_severity?.critical ?? 0)}
              icon={AlertTriangle}
              tone="red"
              hint="À traiter en priorité"
            />
          </div>

          <div className="mt-6 grid grid-cols-1 gap-6 xl:grid-cols-5">
            {/* Répartition des constats */}
            <section className="panel p-5 xl:col-span-2">
              <h2 className="text-sm font-semibold text-slate-200">Constats par sévérité</h2>
              <p className="mt-1 text-xs text-slate-500">
                Répartition cumulée sur l'ensemble des scans.
              </p>
              <div className="mt-4">
                <ResponsiveContainer width="100%" height={260}>
                  <BarChart data={chartData} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                    <XAxis
                      dataKey="severity"
                      tick={{ fill: '#94a3b8', fontSize: 12 }}
                      tickLine={false}
                      axisLine={{ stroke: '#1e293b' }}
                    />
                    <YAxis
                      tick={{ fill: '#94a3b8', fontSize: 12 }}
                      tickLine={false}
                      axisLine={false}
                      allowDecimals={false}
                    />
                    <Tooltip
                      cursor={{ fill: '#0f172a' }}
                      contentStyle={{
                        backgroundColor: '#0f172a',
                        border: '1px solid #1e293b',
                        borderRadius: 8,
                        color: '#e2e8f0',
                        fontSize: 12,
                      }}
                    />
                    <Bar dataKey="count" name="Constats" radius={[4, 4, 0, 0]} maxBarSize={44}>
                      {chartData.map((entry) => (
                        <Cell key={entry.severity} fill={entry.fill} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </section>

            {/* Derniers scans */}
            <section className="panel xl:col-span-3">
              <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
                <div>
                  <h2 className="text-sm font-semibold text-slate-200">Derniers scans</h2>
                  <p className="mt-1 text-xs text-slate-500">Activité la plus récente.</p>
                </div>
                <Link to="/scans" className="btn-ghost text-xs">
                  Tous les scans
                  <ChevronRight className="h-3.5 w-3.5" />
                </Link>
              </div>

              {data.last_scans.length === 0 ? (
                <EmptyState
                  icon={Radar}
                  title="Aucun scan pour le moment"
                  description="Lancez un premier scan depuis la section Scans pour alimenter le tableau de bord."
                />
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-slate-800">
                        <th className="th">ID</th>
                        <th className="th">Cible</th>
                        <th className="th">Profil</th>
                        <th className="th">Statut</th>
                        <th className="th">Date</th>
                        <th className="th">
                          <span className="sr-only">Détails</span>
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.last_scans.map((scan) => (
                        <tr key={scan.id} className="transition-colors hover:bg-slate-800/40">
                          <td className="td font-mono text-xs text-slate-500">#{scan.id}</td>
                          <td className="td">
                            <p className="font-medium text-slate-200">
                              {scan.target?.name ?? `Cible #${scan.target_id}`}
                            </p>
                            {scan.target ? (
                              <p className="font-mono text-xs text-slate-500">
                                {scan.target.value}
                              </p>
                            ) : null}
                          </td>
                          <td className="td text-slate-400">
                            {PROFILE_LABELS[scan.profile] ?? scan.profile}
                          </td>
                          <td className="td">
                            <StatusBadge status={scan.status} />
                          </td>
                          <td className="td text-slate-400">{formatDateTime(scan.created_at)}</td>
                          <td className="td text-right">
                            <Link
                              to={`/scans/${scan.id}`}
                              className="inline-flex rounded p-1 text-slate-500 transition-colors hover:text-cyan-400"
                              title="Voir le détail"
                            >
                              <ChevronRight className="h-4 w-4" />
                            </Link>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          </div>
        </>
      )}
    </div>
  )
}
