import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from './api'
import type { Ioc, IntelOverview } from './types'

/** Les flux de renseignement bougent lentement : inutile de rafraîchir souvent. */
export const INTEL_REFETCH_MS = 60_000

export interface IocFilters {
  type?: string
  source?: string
  severity?: string[]
  search?: string
  limit?: number
}

export function buildIocParams(filters: IocFilters = {}): Record<string, string | number> {
  const params: Record<string, string | number> = { limit: filters.limit ?? 100 }
  if (filters.type) params.type = filters.type
  if (filters.source) params.source = filters.source
  if (filters.search) params.search = filters.search
  if (filters.severity?.length) params.severity = filters.severity.join(',')
  return params
}

export function useIntelOverview() {
  return useQuery({
    queryKey: ['intel', 'overview'],
    queryFn: async (): Promise<IntelOverview> => {
      const { data } = await api.get<IntelOverview>('/intel/overview')
      return data
    },
    refetchInterval: INTEL_REFETCH_MS,
  })
}

export function useIocs(filters: IocFilters = {}) {
  const params = buildIocParams(filters)
  return useQuery({
    queryKey: ['intel', 'iocs', params],
    queryFn: async (): Promise<Ioc[]> => {
      const { data } = await api.get<Ioc[]>('/intel/iocs', { params })
      return data
    },
    refetchInterval: INTEL_REFETCH_MS,
  })
}

/**
 * Déclenche un cycle complet (connecteurs + corrélation) sur le worker.
 * L'API répond 503 si la file est injoignable : le message est affiché tel quel.
 */
export function useIntelSync() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async () => {
      const { data } = await api.post<{ status: string; job_id: string | null; sources: string[] }>(
        '/intel/sync',
      )
      return data
    },
    onSuccess: () => {
      // Les données n'arrivent qu'après le passage du worker : on laisse le
      // rafraîchissement automatique les récupérer plutôt que de boucler.
      queryClient.invalidateQueries({ queryKey: ['intel'] })
    },
  })
}
