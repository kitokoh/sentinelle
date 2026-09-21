// Modèles de données alignés sur l'API Sentinelle.

/** Rôles de la plateforme (v0.5). La hiérarchie est stricte : admin ⊃ analyste ⊃ lecteur. */
export type Role = 'viewer' | 'analyst' | 'admin' | string

export interface User {
  id: number
  email: string
  role: Role
  /** Organisation (tenant) de l'utilisateur. */
  org_id: number
  created_at?: string
}

export interface Organization {
  id: number
  name: string
  slug: string
  members: number
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
  /** Organisation propriétaire du scan. */
  org_id?: number
  profile: ScanProfile
  status: ScanStatus
  created_at: string
  started_at?: string | null
  finished_at?: string | null
  /** Score de risque 0–100 calculé à partir des constats. */
  risk_score: number
  /**
   * Nom et valeur de la cible, **aplatis** par l'API (`ScanWithTarget` /
   * `ScanDetail`). Il n'y a pas d'objet `target` imbriqué : le front lisait un
   * champ inexistant et affichait « Cible #N » à la place du nom.
   */
  target_name: string
  target_value: string
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

/* ---------- v0.4 — Renseignement (threat intel) ---------- */

/** Familles d'indicateurs normalisées par le backend. */
export type IocType = 'ip' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256' | 'email' | string

/** Un indicateur de compromis, dédoublonné entre les sources. */
export interface Ioc {
  id: number
  type: IocType
  value: string
  /** Toutes les sources qui le rapportent, ex. `['misp', 'otx']`. */
  sources: string[]
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | string
  first_seen: string
  last_seen: string
  /** Contexte du flux d'origine (nom de pulse / d'événement). */
  name: string
  tags: string[]
  targeted_countries: string[]
  /** Renseignés uniquement si le flux a fourni des coordonnées. */
  latitude: number | null
  longitude: number | null
}

/** Un avis publié par un CERT. */
export interface IntelFeedItem {
  id: number
  guid: string
  source: string
  title: string
  link: string
  summary: string
  published_at: string
}

/** Une alerte issue de la corrélation IoC ↔ observé. */
export interface IntelMatch {
  id: number
  created_at: string
  severity: string
  event_type: string
  detail: string
  status: string
}

/** Point de la carte des campagnes. */
export interface GeoPoint {
  label: string
  type: IocType
  severity: string
  sources: string
  latitude: number
  longitude: number
  name: string
  targeted_countries: string[]
}

/* ---------- v0.5 — Gouvernance ---------- */

/** Une ligne du journal d'audit (`GET /api/audit`, administrateurs seulement). */
export interface AuditLog {
  id: number
  created_at: string
  actor_id: number | null
  actor_email: string | null
  org_id: number | null
  action: string
  method: string
  path: string
  status_code: number
  entity: string | null
  entity_id: number | null
  ip: string | null
  detail: string
}

export interface IntelOverview {
  counts: {
    iocs: number
    feed_items: number
    matches: number
    matches_recent: number
  }
  by_source: Record<string, number>
  by_type: Record<string, number>
  iocs: Ioc[]
  feed: IntelFeedItem[]
  matches: IntelMatch[]
  geo: GeoPoint[]
}

export interface DashboardStats {
  targets_count: number
  scans_count: number
  findings_count: number
  findings_by_severity: Record<string, number>
  alerts_count: number
  alerts_unacknowledged: number
  last_scans: Scan[]
}

export interface LoginResponse {
  access_token: string
  token_type?: string
}
