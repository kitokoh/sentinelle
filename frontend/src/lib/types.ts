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

/* ---------- v0.3 — Alertes (défense) ---------- */

/** Origine d'une alerte : signature du capteur, règle locale, ou renseignement (v0.4). */
export type AlertSource = 'suricata' | 'rule' | 'intel' | string

/** Cycle de vie d'une alerte : `new` tant qu'elle n'est pas acquittée. */
export type AlertStatus = 'new' | 'ack' | string

export interface Alert {
  id: number
  created_at: string
  source: AlertSource
  event_type: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | string
  src_ip: string | null
  src_port: number | null
  dst_ip: string | null
  dst_port: number | null
  proto: string | null
  /** Renseigné pour les alertes issues du moteur de règles. */
  rule_name: string | null
  /** 0–1 : marge au-dessus du seuil de détection. */
  confidence: number | null
  /** Nombre d'événements ayant alimenté l'alerte (déduplication). */
  occurrences: number
  signature: string | null
  detail: string
  status: AlertStatus
  acknowledged_at: string | null
  acknowledged_by: number | null
}

/** Alerte avec sa charge utile brute (événement EVE d'origine). */
export interface AlertDetail extends Alert {
  payload: string
}

export interface AlertStats {
  total: number
  unacknowledged: number
  by_severity: Record<string, number>
  by_source: Record<string, number>
}

export interface AlertFilters {
  severity?: string[]
  source?: string[]
  status?: string[]
  limit?: number
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
