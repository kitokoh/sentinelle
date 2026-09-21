import { lazy, Suspense, useState } from 'react'
import {
  AlertTriangle,
  ExternalLink,
  Globe2,
  Loader2,
  Newspaper,
  RefreshCw,
  Search,
  Target,
} from 'lucide-react'
import { getApiErrorMessage } from '../lib/api'
import { useIocs, useIntelOverview, useIntelSync } from '../lib/intel'
import { formatNumber, formatRelativeTime } from '../lib/format'
import type { Ioc } from '../lib/types'
import PageHeader from '../components/PageHeader'
import EmptyState from '../components/EmptyState'
import { ErrorState, LoadingState } from '../components/QueryState'
import { AlertStatusBadge, IocTypeBadge, SeverityBadge, SourceList } from '../components/badges'

// Leaflet pèse à lui seul la moitié du bundle : la carte n'est chargée que
// lorsque l'onglet est ouvert, le reste de l'application reste léger.
const CampaignMap = lazy(() => import('../components/CampaignMap'))

const IOC_TYPES = ['ip', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email'] as const

function IocRow({ ioc }: { ioc: Ioc }) {
  return (
    <tr className="transition-colors hover:bg-slate-800/40">
      <td className="td">
        <IocTypeBadge type={ioc.type} />
      </td>
      <td className="td">
        <p className="font-mono text-xs text-slate-200">{ioc.value}</p>
        {ioc.name ? (
          <p className="mt-0.5 max-w-[360px] truncate text-xs text-slate-500" title={ioc.name}>
            {ioc.name}
          </p>
        ) : null}
      </td>
      <td className="td">
        <SeverityBadge severity={ioc.severity} />
      </td>
      <td className="td">
        <SourceList sources={ioc.sources} />
      </td>
      <td className="td text-slate-400">{formatRelativeTime(ioc.last_seen)}</td>
    </tr>
  )
}

export default function IntelPage() {
  const [type, setType] = useState('')
  const [source, setSource] = useState('')
  const [search, setSearch] = useState('')
  const [syncMessage, setSyncMessage] = useState<string | null>(null)
  const [syncError, setSyncError] = useState<string | null>(null)

  const overview = useIntelOverview()
  const iocs = useIocs({ type, source, search })
  const sync = useIntelSync()

  const counts = overview.data?.counts
  const geo = overview.data?.geo ?? []
  const feed = overview.data?.feed ?? []
  const matches = overview.data?.matches ?? []

  function handleSync() {
    setSyncMessage(null)
    setSyncError(null)
    sync.mutate(undefined, {
      onSuccess: (data) =>
        setSyncMessage(
          `Cycle lancé sur le worker (job ${data.job_id ?? '—'}) : ${data.sources.join(', ') || 'aucune source configurée'}.`,
        ),
      onError: (error) => setSyncError(getApiErrorMessage(error)),
    })
  }

  return (
    <div>
      <PageHeader
        title="Renseignement"
        description="Veille CERT, indicateurs de compromis (MISP / OTX) et corrélation avec ce que la plateforme a observé."
      >
        <button type="button" className="btn-primary" onClick={handleSync} disabled={sync.isPending}>
          {sync.isPending ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <RefreshCw className="h-4 w-4" />
          )}
          Synchroniser
        </button>
      </PageHeader>

      {syncMessage ? (
        <div className="mb-4 rounded-md border border-cyan-400/30 bg-cyan-400/10 px-3 py-2.5 text-sm text-cyan-300">
          {syncMessage}
        </div>
      ) : null}
      {syncError ? (
        <div className="mb-4 flex items-start gap-2 rounded-md border border-red-400/30 bg-red-400/10 px-3 py-2.5 text-sm text-red-400">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>{syncError}</span>
        </div>
      ) : null}

      {/* Compteurs */}
      <section className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <div className="panel p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
            Indicateurs
          </p>
          <p className="mt-1 text-2xl font-semibold tabular-nums text-slate-200">
            {formatNumber(counts?.iocs)}
          </p>
        </div>
        <div className="panel p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
            Avis CERT
          </p>
          <p className="mt-1 text-2xl font-semibold tabular-nums text-cyan-400">
            {formatNumber(counts?.feed_items)}
          </p>
        </div>
        <div className="panel p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
            Correspondances
          </p>
          <p className="mt-1 text-2xl font-semibold tabular-nums text-orange-400">
            {formatNumber(counts?.matches)}
          </p>
        </div>
        <div className="panel p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
            Sur 7 jours
          </p>
          <p className="mt-1 text-2xl font-semibold tabular-nums text-red-400">
            {formatNumber(counts?.matches_recent)}
          </p>
        </div>
      </section>

      {/* Carte des campagnes */}
      <section className="panel mb-6">
        <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
          <div className="flex items-center gap-2">
            <Globe2 className="h-4 w-4 text-cyan-400" />
            <h2 className="text-sm font-semibold text-slate-200">Carte des campagnes</h2>
          </div>
          <span className="text-xs text-slate-500">
            {geo.length > 0 ? `${geo.length} indicateur(s) géolocalisé(s) à la source` : ''}
          </span>
        </div>
        <Suspense fallback={<LoadingState label="Chargement de la carte…" />}>
          <CampaignMap points={geo} />
        </Suspense>
      </section>

      {/* Correspondances + veille */}
      <div className="mb-6 grid grid-cols-1 gap-6 xl:grid-cols-2">
        <section className="panel">
          <div className="border-b border-slate-800 px-5 py-4">
            <div className="flex items-center gap-2">
              <Target className="h-4 w-4 text-orange-400" />
              <h2 className="text-sm font-semibold text-slate-200">
                Correspondances locales{matches.length ? ` (${matches.length})` : ''}
              </h2>
            </div>
            <p className="mt-1 text-xs text-slate-500">
              Indicateurs retrouvés dans les alertes et constats — sévérité minimale « élevée ».
            </p>
          </div>

          {overview.isPending ? (
            <LoadingState />
          ) : overview.isError ? (
            <ErrorState
              message={getApiErrorMessage(overview.error)}
              onRetry={() => overview.refetch()}
            />
          ) : matches.length === 0 ? (
            <EmptyState
              icon={Target}
              title="Aucune correspondance"
              description="Aucun indicateur détenu ne correspond à ce qui a été observé. Lancez une synchronisation puis un scan du lab."
            />
          ) : (
            <ul className="divide-y divide-slate-800">
              {matches.map((match) => (
                <li key={match.id} className="flex items-start gap-3 px-5 py-3">
                  <SeverityBadge severity={match.severity} />
                  <div className="min-w-0 flex-1">
                    <p className="text-xs text-slate-300">{match.detail}</p>
                    <p className="mt-1 text-[11px] text-slate-500">
                      {formatRelativeTime(match.created_at)} · {match.event_type}
                    </p>
                  </div>
                  <AlertStatusBadge status={match.status} />
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="panel">
          <div className="border-b border-slate-800 px-5 py-4">
            <div className="flex items-center gap-2">
              <Newspaper className="h-4 w-4 text-cyan-400" />
              <h2 className="text-sm font-semibold text-slate-200">
                Veille CERT{feed.length ? ` (${feed.length})` : ''}
              </h2>
            </div>
            <p className="mt-1 text-xs text-slate-500">
              Avis agrégés depuis les flux configurés, dédoublonnés par GUID.
            </p>
          </div>

          {overview.isPending ? (
            <LoadingState />
          ) : feed.length === 0 ? (
            <EmptyState
              icon={Newspaper}
              title="Aucun avis collecté"
              description="Configurez CERT_FEEDS puis lancez une synchronisation."
            />
          ) : (
            <ul className="divide-y divide-slate-800">
              {feed.map((item) => (
                <li key={item.id} className="px-5 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <p className="text-xs font-medium text-slate-200">{item.title}</p>
                    <span className="shrink-0 rounded-full border border-slate-700 bg-slate-800/70 px-2 py-0.5 font-mono text-[10px] uppercase text-slate-400">
                      {item.source}
                    </span>
                  </div>
                  {item.summary ? (
                    <p className="mt-1 line-clamp-2 text-[11px] text-slate-500">{item.summary}</p>
                  ) : null}
                  <p className="mt-1 text-[11px] text-slate-600">
                    {formatRelativeTime(item.published_at)}
                    {item.link ? (
                      <a
                        href={item.link}
                        target="_blank"
                        rel="noreferrer"
                        className="ml-2 inline-flex items-center gap-1 text-cyan-400 hover:underline"
                      >
                        consulter <ExternalLink className="h-3 w-3" />
                      </a>
                    ) : null}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      {/* Indicateurs */}
      <section className="panel">
        <div className="flex flex-wrap items-end justify-between gap-3 border-b border-slate-800 px-5 py-4">
          <div>
            <h2 className="text-sm font-semibold text-slate-200">
              Indicateurs de compromis{iocs.data ? ` (${iocs.data.length})` : ''}
            </h2>
            <p className="mt-1 text-xs text-slate-500">
              Un indicateur rapporté par plusieurs flux reste une seule ligne, avec toutes ses
              provenances.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <select
              className="input max-w-[160px]"
              value={type}
              onChange={(event) => setType(event.target.value)}
              aria-label="Filtrer par type"
            >
              <option value="">Tous les types</option>
              {IOC_TYPES.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
            <select
              className="input max-w-[160px]"
              value={source}
              onChange={(event) => setSource(event.target.value)}
              aria-label="Filtrer par source"
            >
              <option value="">Toutes les sources</option>
              <option value="misp">MISP</option>
              <option value="otx">OTX</option>
            </select>
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
              <input
                className="input max-w-[220px] pl-8"
                placeholder="Rechercher une valeur…"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                aria-label="Rechercher un indicateur"
              />
            </div>
          </div>
        </div>

        {iocs.isPending ? (
          <LoadingState label="Chargement des indicateurs…" />
        ) : iocs.isError ? (
          <ErrorState message={getApiErrorMessage(iocs.error)} onRetry={() => iocs.refetch()} />
        ) : (iocs.data ?? []).length === 0 ? (
          <EmptyState
            icon={Globe2}
            title="Aucun indicateur"
            description="Configurez MISP_URL / OTX_API_KEY puis lancez une synchronisation."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-800">
                  <th className="th">Type</th>
                  <th className="th">Valeur</th>
                  <th className="th">Sévérité</th>
                  <th className="th">Sources</th>
                  <th className="th">Vu</th>
                </tr>
              </thead>
              <tbody>
                {(iocs.data ?? []).map((ioc) => (
                  <IocRow key={ioc.id} ioc={ioc} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}
