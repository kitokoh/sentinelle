import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, Download, FileText, Loader2 } from 'lucide-react'
import { api, getApiErrorMessage } from '../lib/api'
import { formatDateTime, formatNumber } from '../lib/format'
import type { Scan } from '../lib/types'
import PageHeader from '../components/PageHeader'
import EmptyState from '../components/EmptyState'
import { ErrorState, LoadingState } from '../components/QueryState'
import { ProfileBadge, RiskBadge, StatusBadge } from '../components/badges'

async function fetchScans(): Promise<Scan[]> {
  const { data } = await api.get<Scan[]>('/scans')
  return data
}

/** Télécharge un document binaire produit par l'API (PDF ou CSV). */
async function downloadDocument(path: string, filename: string): Promise<void> {
  const response = await api.get(path, { responseType: 'blob' })
  const url = URL.createObjectURL(response.data as Blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}

export default function ReportsPage() {
  const [busy, setBusy] = useState<string | null>(null)
  const [downloadError, setDownloadError] = useState<string | null>(null)

  const { data, isPending, isError, error, refetch } = useQuery({
    queryKey: ['scans'],
    queryFn: fetchScans,
    refetchInterval: 15_000,
  })

  const scans = data ?? []
  // Seuls les scans terminés ont de quoi produire un rapport utile.
  const reportable = scans.filter((scan) => scan.status === 'done')

  async function handleDownload(scan: Scan, kind: 'pdf' | 'csv') {
    setDownloadError(null)
    setBusy(`${scan.id}-${kind}`)
    try {
      const path = kind === 'pdf' ? `/scans/${scan.id}/report.pdf` : `/scans/${scan.id}/export`
      const filename = kind === 'pdf' ? `rapport_scan_${scan.id}.pdf` : `scan_${scan.id}_findings.csv`
      await downloadDocument(path, filename)
    } catch {
      setDownloadError('Téléchargement impossible — le scan a peut-être été supprimé.')
    } finally {
      setBusy(null)
    }
  }

  return (
    <div>
      <PageHeader
        title="Rapports"
        description="Comptes rendus d'audit horodatés : synthèse dirigeant, annexe technique et constats exportables."
      />

      {downloadError ? (
        <div className="mb-4 flex items-start gap-2 rounded-md border border-red-400/30 bg-red-400/10 px-3 py-2.5 text-sm text-red-400">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>{downloadError}</span>
        </div>
      ) : null}

      <section className="panel mb-6 p-5">
        <h2 className="text-sm font-semibold text-slate-200">Ce que contient le rapport PDF</h2>
        <ul className="mt-3 grid grid-cols-1 gap-2 text-sm text-slate-400 md:grid-cols-2">
          <li>• Page 1 — synthèse non technique : score, niveau de risque, points saillants</li>
          <li>• Recommandations dérivées des constats, justifiables une par une</li>
          <li>• Page 2 — annexe technique : tableau exhaustif des constats</li>
          <li>• Nom de la cible, autorisation, horodatage et auteur du rapport</li>
        </ul>
      </section>

      <section className="panel">
        <div className="border-b border-slate-800 px-5 py-4">
          <h2 className="text-sm font-semibold text-slate-200">
            Rapports disponibles{data ? ` (${reportable.length}/${scans.length})` : ''}
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            Un rapport par scan terminé. Le rapport PDF est refusé si le scan appartient à une autre
            organisation.
          </p>
        </div>

        {isPending ? (
          <LoadingState />
        ) : isError ? (
          <ErrorState message={getApiErrorMessage(error)} onRetry={() => refetch()} />
        ) : scans.length === 0 ? (
          <EmptyState
            icon={FileText}
            title="Aucun scan à rapporter"
            description="Lancez un scan depuis la page Scans : son rapport apparaîtra ici dès la fin de l'exécution."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-800">
                  <th className="th">Scan</th>
                  <th className="th">Cible</th>
                  <th className="th">Profil</th>
                  <th className="th">Statut</th>
                  <th className="th">Risque</th>
                  <th className="th">Date</th>
                  <th className="th text-right">Rapport</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr key={scan.id} className="transition-colors hover:bg-slate-800/40">
                    <td className="td">
                      <Link to={`/scans/${scan.id}`} className="font-mono text-xs text-cyan-400 hover:underline">
                        #{scan.id}
                      </Link>
                    </td>
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
                    <td className="td">
                      <RiskBadge score={scan.risk_score} size="sm" />
                    </td>
                    <td className="td text-slate-400">{formatDateTime(scan.created_at)}</td>
                    <td className="td">
                      <div className="flex justify-end gap-2">
                        <button
                          type="button"
                          className="btn-primary"
                          disabled={scan.status !== 'done' || busy === `${scan.id}-pdf`}
                          onClick={() => handleDownload(scan, 'pdf')}
                          title={
                            scan.status === 'done'
                              ? 'Télécharger le rapport PDF'
                              : 'Disponible à la fin du scan'
                          }
                        >
                          {busy === `${scan.id}-pdf` ? (
                            <Loader2 className="h-3.5 w-3.5 animate-spin" />
                          ) : (
                            <FileText className="h-3.5 w-3.5" />
                          )}
                          PDF
                        </button>
                        <button
                          type="button"
                          className="btn-ghost"
                          disabled={scan.status !== 'done' || busy === `${scan.id}-csv`}
                          onClick={() => handleDownload(scan, 'csv')}
                          title="Exporter les constats (CSV)"
                        >
                          {busy === `${scan.id}-csv` ? (
                            <Loader2 className="h-3.5 w-3.5 animate-spin" />
                          ) : (
                            <Download className="h-3.5 w-3.5" />
                          )}
                          CSV
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="px-5 py-3 text-xs text-slate-600">
              {formatNumber(reportable.length)} rapport(s) prêt(s) à diffusion.
            </p>
          </div>
        )}
      </section>
    </div>
  )
}
