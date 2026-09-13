// Modèles de données alignés sur l'API Sentinelle.

export interface User {
  id: number
  email: string
  role: string
}

export type TargetKind = 'ip' | 'hostname' | 'cidr'

/** `allowed` = dans le périmètre autorisé, `denied` = hors périmètre / refusée. */
export type ScopeStatus = 'allowed' | 'denied' | string

export interface Target {
  id: number
  name: string
  value: string
  kind: TargetKind
  scope_status: ScopeStatus
  authorization_reference: string | null
  /** Score de risque agrégé 0–100 (0 = non évalué). */
  risk_score: number
}

export interface NewTarget {
  name: string
  value: string
  kind: TargetKind
  authorization_reference: string | null
}

export type ScanProfile = 'quick' | 'full'

export type ScanStatus = 'pending' | 'running' | 'done' | 'failed' | 'denied' | string

export interface Scan {
  id: number
  target_id: number
  profile: ScanProfile
  status: ScanStatus
  created_at: string
  started_at?: string | null
  finished_at?: string | null
  /** Score de risque 0–100 calculé à partir des constats. */
  risk_score: number
  target?: Target
}

/** Outil à l'origine du constat. */
export type FindingSource = 'nmap' | 'nuclei' | 'nvd' | string

export interface Finding {
  id: number
  port: number
  protocol: string
  service: string
  version: string | null
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | string
  source: FindingSource
  detail: string | null
}

export interface ScanDetail extends Scan {
  findings: Finding[]
}

export interface DashboardStats {
  targets: number
  scans: number
  findings: number
  findings_by_severity: Record<string, number>
  last_scans: Scan[]
}

export interface LoginResponse {
  access_token: string
  token_type?: string
}
