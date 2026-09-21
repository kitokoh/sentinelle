import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from './api'
import type { Alert, AlertFilters, AlertStats } from './types'

/** Le flux d'alertes est vivant : on rafraîchit sans que l'analyste ait à cliquer. */
export const ALERTS_REFETCH_MS = 5_000

/**
 * L'API FastAPI attend des paramètres répétés (`?severity=high&severity=low`)
 * ou une liste séparée par des virgules. Axios sérialiserait un tableau en
 * `severity[]=…`, d'où la jointure explicite par des virgules.
 */
export function buildAlertParams(filters: AlertFilters = {}): Record<string, string | number> {
  const params: Record<string, string | number> = { limit: filters.limit ?? 200 }
  if (filters.severity?.length) params.severity = filters.severity.join(',')
  if (filters.source?.length) params.source = filters.source.join(',')
  if (filters.status?.length) params.status = filters.status.join(',')
  return params
}

export function useAlertStats() {
  return useQuery({
    queryKey: ['alerts', 'stats'],
    queryFn: async (): Promise<AlertStats> => {
      const { data } = await api.get<AlertStats>('/alerts/stats')
      return data
    },
    refetchInterval: ALERTS_REFETCH_MS,
  })
}

export function useAlerts(filters: AlertFilters = {}) {
  const params = buildAlertParams(filters)
  return useQuery({
    queryKey: ['alerts', 'list', params],
    queryFn: async (): Promise<Alert[]> => {
      const { data } = await api.get<Alert[]>('/alerts', { params })
      return data
    },
    refetchInterval: ALERTS_REFETCH_MS,
  })
}

/** Acquittement / réouverture d'une alerte (PATCH /api/alerts/{id}). */
export function useAcknowledgeAlert() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ id, status }: { id: number; status: 'ack' | 'new' }) => {
      const { data } = await api.patch<Alert>(`/alerts/${id}`, { status })
      return data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] })
      queryClient.invalidateQueries({ queryKey: ['dashboard'] })
    },
  })
}
