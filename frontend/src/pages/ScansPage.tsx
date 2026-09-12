import { useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, ChevronRight, Loader2, Play, Radar } from 'lucide-react'
import { api, getApiErrorMessage } from '../lib/api'
import { formatDateTime } from '../lib/format'
import type { Scan, ScanProfile, Target } from '../lib/types'
import PageHeader from '../components/PageHeader'
import EmptyState from '../components/EmptyState'
import { ErrorState, LoadingState } from '../components/QueryState'
import { ProfileBadge, StatusBadge } from '../components/badges'

async function fetchScans(): Promise<Scan[]> {
  const { data } = await api.get<Scan[]>('/scans')
  return data
}

async function fetchTargets(): Promise<Target[]> {
  const { data } = await api.get<Target[]>('/targets')
  return data
}

export default function ScansPage() {
  const queryClient = useQueryClient()
  const [targetId, setTargetId] = useState('')
  const [profile, setProfile] = useState<ScanProfile>('quick')
  const [formError, setFormError] = useState<string | null>(null)

  const targetsQuery = useQuery({ queryKey: ['targets'], queryFn: fetchTargets })
  const { data, isPending, isError, error, refetch } = useQuery({
    queryKey: ['scans'],
    queryFn: fetchScans,
    refetchInterval: 4_000,
  })

  // Seules les cibles autorisées peuvent être scannées.
  const allowedTargets = (targetsQuery.data ?? []).filter((t) => t.scope_status === 'allowed')

  const launchScan = useMutation({
    mutationFn: async (payload: { target_id: number; profile: ScanProfile }) => {
      await api.post('/scans', payload)
    },
    onSuccess: () => {
      setTargetId('')
      setProfile('quick')
      setFormError(null)
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      queryClient.invalidateQueries({ queryKey: ['dashboard'] })
    },
    onError: (err) => setFormError(getApiErrorMessage(err)),
  })

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setFormError(null)
    const id = Number(targetId)
    if (!Number.isInteger(id) || id <= 0) {
      setFormError('Sélectionnez une cible autorisée.')
      return
    }
    launchScan.mutate({ target_id: id, profile })
  }

  return (
    <div>
      <PageHeader
        title="Scans"
        description="Campagnes de reconnaissance réseau sur les cibles autorisées."
      />

      {/* Lancement d'un scan */}
      <section className="panel mb-6 p-5">
        <h2 className="text-sm font-semibold text-slate-200">Lancer un scan</h2>
        <form
          onSubmit={handleSubmit}
          className="mt-4 grid grid-cols-1 items-end gap-4 md:grid-cols-3"
        >
          <div>
            <label htmlFor="scan-target" className="label">
              Cible
            </label>
            <select
              id="scan-target"
              className="input"
              value={targetId}
              onChange={(e) => setTargetId(e.target.value)}
              disabled={targetsQuery.isPending}
            >
              <option value="">— Sélectionner une cible autorisée —</option>
              {allowedTargets.map((target) => (
                <option key={target.id} value={target.id}>
                  {target.name} ({target.value})
                </option>
              ))}
            </select>
            {!targetsQuery.isPending && allowedTargets.length === 0 ? (
              <p className="helper">
                Aucune cible autorisée — déclarez-en une dans la section{' '}
                <Link to="/cibles" className="text-cyan-400 hover:underline">
                  Cibles
                </Link>
                .
              </p>
            ) : null}
          </div>

          <div>
            <label htmlFor="scan-profile" className="label">
              Profil
            </label>
            <select
              id="scan-profile"
              className="input"
              value={profile}
              onChange={(e) => setProfile(e.target.value as ScanProfile)}
            >
              <option value="quick">Rapide — ports courants</option>
              <option value="full">Complet — 1–65535</option>
            </select>
          </div>

          <div>
            <button
              type="submit"
              className="btn-primary w-full md:w-auto"
              disabled={launchScan.isPending || !targetId}
            >
              {launchScan.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Play className="h-4 w-4" />
              )}
              Lancer le scan
            </button>
          </div>

          {formError ? (
            <div className="flex items-start gap-2 rounded-md border border-red-400/30 bg-red-400/10 px-3 py-2.5 text-sm text-red-400 md:col-span-3">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{formError}</span>
            </div>
          ) : null}
        </form>
      </section>

      {/* Historique */}
      <section className="panel">
        <div className="border-b border-slate-800 px-5 py-4">
          <h2 className="text-sm font-semibold text-slate-200">
            Historique des scans{data ? ` (${data.length})` : ''}
          </h2>
          <p className="mt-1 text-xs text-slate-500">Actualisation automatique toutes les 4 s.</p>
        </div>

        {isPending ? (
          <LoadingState />
        ) : isError ? (
          <ErrorState message={getApiErrorMessage(error)} onRetry={() => refetch()} />
        ) : data.length === 0 ? (
          <EmptyState
            icon={Radar}
            title="Aucun scan exécuté"
            description="Sélectionnez une cible autorisée ci-dessus pour lancer la première campagne."
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
                {data.map((scan) => (
                  <tr key={scan.id} className="transition-colors hover:bg-slate-800/40">
                    <td className="td font-mono text-xs text-slate-500">#{scan.id}</td>
                    <td className="td">
                      <p className="font-medium text-slate-200">
                        {scan.target?.name ?? `Cible #${scan.target_id}`}
                      </p>
                      {scan.target ? (
                        <p className="font-mono text-xs text-slate-500">{scan.target.value}</p>
                      ) : null}
                    </td>
                    <td className="td">
                      <ProfileBadge profile={scan.profile} />
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
  )
}
