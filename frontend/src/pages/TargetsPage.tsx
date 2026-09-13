import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Crosshair, Loader2, Plus, ShieldCheck, Trash2 } from 'lucide-react'
import { api, getApiErrorMessage } from '../lib/api'
import type { NewTarget, Target, TargetKind } from '../lib/types'
import PageHeader from '../components/PageHeader'
import EmptyState from '../components/EmptyState'
import { ErrorState, LoadingState } from '../components/QueryState'
import { KindBadge, RiskBadge, ScopeBadge } from '../components/badges'

interface TargetFormState {
  name: string
  value: string
  kind: TargetKind
  authorization_reference: string
}

const EMPTY_FORM: TargetFormState = {
  name: '',
  value: '',
  kind: 'ip',
  authorization_reference: '',
}

async function fetchTargets(): Promise<Target[]> {
  const { data } = await api.get<Target[]>('/targets')
  return data
}

export default function TargetsPage() {
  const queryClient = useQueryClient()
  const [form, setForm] = useState<TargetFormState>(EMPTY_FORM)
  const [formError, setFormError] = useState<string | null>(null)

  const { data, isPending, isError, error, refetch } = useQuery({
    queryKey: ['targets'],
    queryFn: fetchTargets,
  })

  const createTarget = useMutation({
    mutationFn: async (payload: NewTarget) => {
      await api.post('/targets', payload)
    },
    onSuccess: () => {
      setForm(EMPTY_FORM)
      setFormError(null)
      queryClient.invalidateQueries({ queryKey: ['targets'] })
      queryClient.invalidateQueries({ queryKey: ['dashboard'] })
    },
    onError: (err) => setFormError(getApiErrorMessage(err)),
  })

  const deleteTarget = useMutation({
    mutationFn: async (id: number) => {
      await api.delete(`/targets/${id}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['targets'] })
      queryClient.invalidateQueries({ queryKey: ['dashboard'] })
    },
  })

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setFormError(null)
    createTarget.mutate({
      name: form.name.trim(),
      value: form.value.trim(),
      kind: form.kind,
      authorization_reference: form.authorization_reference.trim() || null,
    })
  }

  function handleDelete(target: Target) {
    if (window.confirm(`Supprimer la cible « ${target.name} » ? Cette action est définitive.`)) {
      deleteTarget.mutate(target.id)
    }
  }

  return (
    <div>
      <PageHeader
        title="Cibles"
        description="Registre des actifs autorisés à être audités par la plateforme."
      />

      {/* Rappel de la règle d'engagement */}
      <div className="panel mb-6 flex gap-3 border-cyan-400/20 bg-cyan-400/5 p-4">
        <ShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-cyan-400" />
        <div className="text-sm">
          <p className="font-medium text-cyan-300">Scans limités aux cibles autorisées</p>
          <p className="mt-1 leading-relaxed text-slate-400">
            Sentinelle n'exécute de scans que sur des cibles déclarées et explicitement autorisées.
            Toute cible hors du périmètre « lab » doit être accompagnée d'une référence
            d'autorisation écrite. Les cibles refusées ne peuvent faire l'objet d'aucun scan.
          </p>
        </div>
      </div>

      {/* Formulaire d'ajout */}
      <section className="panel mb-6 p-5">
        <h2 className="text-sm font-semibold text-slate-200">Déclarer une nouvelle cible</h2>
        <form onSubmit={handleSubmit} className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
          <div>
            <label htmlFor="target-name" className="label">
              Nom
            </label>
            <input
              id="target-name"
              className="input"
              required
              placeholder="Passerelle VPN"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
          </div>
          <div>
            <label htmlFor="target-value" className="label">
              Valeur
            </label>
            <input
              id="target-value"
              className="input font-mono"
              required
              placeholder="192.0.2.10 ou vpn.exemple.fr"
              value={form.value}
              onChange={(e) => setForm({ ...form, value: e.target.value })}
            />
          </div>
          <div>
            <label htmlFor="target-kind" className="label">
              Type
            </label>
            <select
              id="target-kind"
              className="input"
              value={form.kind}
              onChange={(e) => setForm({ ...form, kind: e.target.value as TargetKind })}
            >
              <option value="ip">IP</option>
              <option value="hostname">Nom d'hôte</option>
              <option value="cidr">CIDR</option>
            </select>
          </div>
          <div>
            <label htmlFor="target-auth" className="label">
              Référence d'autorisation
            </label>
            <input
              id="target-auth"
              className="input font-mono"
              placeholder="EX-AUTO-2026-0142"
              value={form.authorization_reference}
              onChange={(e) => setForm({ ...form, authorization_reference: e.target.value })}
            />
            <p className="helper">
              Obligatoire pour une cible hors périmètre lab — attestation écrite requise
            </p>
          </div>

          <div className="md:col-span-2 xl:col-span-4">
            {formError ? (
              <div className="mb-3 flex items-start gap-2 rounded-md border border-red-400/30 bg-red-400/10 px-3 py-2.5 text-sm text-red-400">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{formError}</span>
              </div>
            ) : null}
            <button type="submit" className="btn-primary" disabled={createTarget.isPending}>
              {createTarget.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Plus className="h-4 w-4" />
              )}
              Ajouter la cible
            </button>
          </div>
        </form>
      </section>

      {/* Registre */}
      <section className="panel">
        <div className="border-b border-slate-800 px-5 py-4">
          <h2 className="text-sm font-semibold text-slate-200">
            Registre des cibles{data ? ` (${data.length})` : ''}
          </h2>
        </div>

        {isPending ? (
          <LoadingState />
        ) : isError ? (
          <ErrorState message={getApiErrorMessage(error)} onRetry={() => refetch()} />
        ) : data.length === 0 ? (
          <EmptyState
            icon={Crosshair}
            title="Aucune cible déclarée"
            description="Déclarez une première cible autorisée via le formulaire ci-dessus."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-800">
                  <th className="th">Nom</th>
                  <th className="th">Valeur</th>
                  <th className="th">Type</th>
                  <th className="th">Périmètre</th>
                  <th className="th">Risque</th>
                  <th className="th">Réf. d'autorisation</th>
                  <th className="th">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {data.map((target) => (
                  <tr key={target.id} className="transition-colors hover:bg-slate-800/40">
                    <td className="td font-medium text-slate-200">{target.name}</td>
                    <td className="td font-mono text-xs text-slate-300">{target.value}</td>
                    <td className="td">
                      <KindBadge kind={target.kind} />
                    </td>
                    <td className="td">
                      <ScopeBadge status={target.scope_status} />
                    </td>
                    <td className="td">
                      <RiskBadge score={target.risk_score} />
                    </td>
                    <td className="td font-mono text-xs text-slate-500">
                      {target.authorization_reference ?? '—'}
                    </td>
                    <td className="td text-right">
                      <button
                        type="button"
                        onClick={() => handleDelete(target)}
                        disabled={deleteTarget.isPending}
                        title="Supprimer la cible"
                        className="inline-flex rounded p-1.5 text-slate-500 transition-colors hover:bg-red-400/10 hover:text-red-400 disabled:opacity-50"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
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
