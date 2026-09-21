import { useQuery } from '@tanstack/react-query'
import { api } from './api'
import type { AuditLog } from './types'

/** Le journal n'est lu que par un administrateur : inutile de le poller vite. */
export const AUDIT_REFETCH_MS = 30_000

export interface AuditFilters {
  actor?: string
  action?: string
  entity?: string
  entity_id?: number
  since?: string
  until?: string
  limit?: number
}

export function buildAuditParams(filters: AuditFilters = {}): Record<string, string | number> {
  const params: Record<string, string | number> = { limit: filters.limit ?? 200 }
  if (filters.actor) params.actor = filters.actor
  if (filters.action) params.action = filters.action
  if (filters.entity) params.entity = filters.entity
  if (filters.entity_id !== undefined) params.entity_id = filters.entity_id
  if (filters.since) params.since = filters.since
  if (filters.until) params.until = filters.until
  return params
}

export function useAuditLog(filters: AuditFilters = {}) {
  const params = buildAuditParams(filters)
  return useQuery({
    queryKey: ['audit', 'list', params],
    queryFn: async (): Promise<AuditLog[]> => {
      const { data } = await api.get<AuditLog[]>('/audit', { params })
      return data
    },
    refetchInterval: AUDIT_REFETCH_MS,
  })
}

export function useAuditActions() {
  return useQuery({
    queryKey: ['audit', 'actions'],
    queryFn: async (): Promise<string[]> => {
      const { data } = await api.get<string[]>('/audit/actions')
      return data
    },
    staleTime: 5 * 60_000,
  })
}
