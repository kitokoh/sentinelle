import { CheckCheck, ShieldAlert, ShieldCheck } from 'lucide-react'
import { KIND_LABELS } from '../lib/format'

/* ---------- Statut de scan ---------- */

const STATUS_META: Record<string, { label: string; classes: string; pulse?: boolean }> = {
  pending: { label: 'En attente', classes: 'border-amber-400/30 bg-amber-400/10 text-amber-400' },
  running: {
    label: 'En cours',
    classes: 'border-cyan-400/30 bg-cyan-400/10 text-cyan-400',
    pulse: true,
  },
  done: { label: 'Terminé', classes: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-400' },
  failed: { label: 'Échec', classes: 'border-red-400/30 bg-red-400/10 text-red-400' },
  denied: { label: 'Refusé', classes: 'border-red-400/30 bg-red-400/10 text-red-400' },
}

export function StatusBadge({ status }: { status: string }) {
  const meta = STATUS_META[status] ?? {
    label: status,
    classes: 'border-slate-700 bg-slate-800 text-slate-400',
  }
  return (
    <span className={`badge ${meta.classes} ${meta.pulse ? 'animate-pulse' : ''}`}>
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {meta.label}
    </span>
  )
}

/* ---------- Sévérité d'un constat ---------- */

const SEVERITY_META: Record<string, { label: string; classes: string }> = {
  critical: { label: 'Critique', classes: 'border-red-400/30 bg-red-400/10 text-red-400' },
  high: { label: 'Élevée', classes: 'border-orange-400/30 bg-orange-400/10 text-orange-400' },
  medium: { label: 'Moyenne', classes: 'border-amber-400/30 bg-amber-400/10 text-amber-400' },
  low: { label: 'Faible', classes: 'border-cyan-400/30 bg-cyan-400/10 text-cyan-400' },
  info: { label: 'Info', classes: 'border-slate-600 bg-slate-800 text-slate-400' },
}

export function SeverityBadge({ severity }: { severity: string }) {
  const meta = SEVERITY_META[severity] ?? {
    label: severity,
    classes: 'border-slate-700 bg-slate-800 text-slate-400',
  }
  return <span className={`badge ${meta.classes}`}>{meta.label}</span>
}

/* ---------- Périmètre d'une cible ---------- */

export function ScopeBadge({ status }: { status: string }) {
  if (status === 'allowed') {
    return (
      <span className="badge border-emerald-400/30 bg-emerald-400/10 text-emerald-400">
        <ShieldCheck className="h-3.5 w-3.5" />
        Autorisée
      </span>
    )
  }
  if (status === 'denied') {
    return (
      <span className="badge border-red-400/30 bg-red-400/10 text-red-400">
        <ShieldAlert className="h-3.5 w-3.5" />
        Refusée
      </span>
    )
  }
  return <span className="badge border-slate-700 bg-slate-800 text-slate-400">{status}</span>
}

/* ---------- Type de cible ---------- */

export function KindBadge({ kind }: { kind: string }) {
  return (
    <span className="badge border-slate-700 bg-slate-800 font-mono uppercase text-slate-400">
      {KIND_LABELS[kind] ?? kind}
    </span>
  )
}

/* ---------- Profil de scan ---------- */

export function ProfileBadge({ profile }: { profile: string }) {
  const label = profile === 'full' ? 'Complet' : 'Rapide'
  const classes =
    profile === 'full'
      ? 'border-cyan-400/30 bg-cyan-400/10 text-cyan-400'
      : 'border-slate-700 bg-slate-800 text-slate-400'
  return <span className={`badge ${classes}`}>{label}</span>
}

/* ---------- Source d'un constat ---------- */

const SOURCE_META: Record<string, string> = {
  nmap: 'border-cyan-400/40 bg-cyan-400/5 text-cyan-400',
  nuclei: 'border-violet-400/40 bg-violet-400/10 text-violet-400',
  nvd: 'border-orange-400/40 bg-orange-400/10 text-orange-400',
}

export function SourceBadge({ source }: { source: string }) {
  const classes = SOURCE_META[source] ?? 'border-slate-700 bg-slate-800 text-slate-400'
  return (
    <span
      className={`inline-flex items-center whitespace-nowrap rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${classes}`}
    >
      {source}
    </span>
  )
}

/* ---------- Source d'une alerte (v0.3) ---------- */

const ALERT_SOURCE_META: Record<string, { label: string; classes: string }> = {
  suricata: { label: 'Suricata', classes: 'border-cyan-400/40 bg-cyan-400/5 text-cyan-400' },
  rule: { label: 'Règle locale', classes: 'border-violet-400/40 bg-violet-400/10 text-violet-400' },
  intel: { label: 'Renseignement', classes: 'border-orange-400/40 bg-orange-400/10 text-orange-400' },
}

export function AlertSourceBadge({ source }: { source: string }) {
  const meta = ALERT_SOURCE_META[source] ?? {
    label: source,
    classes: 'border-slate-700 bg-slate-800 text-slate-400',
  }
  return (
    <span
      className={`inline-flex items-center whitespace-nowrap rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${meta.classes}`}
    >
      {meta.label}
    </span>
  )
}

/* ---------- Cycle de vie d'une alerte ---------- */

export function AlertStatusBadge({ status }: { status: string }) {
  if (status === 'ack') {
    return (
      <span className="badge border-slate-700 bg-slate-800 text-slate-400">
        <CheckCheck className="h-3.5 w-3.5" />
        Acquittée
      </span>
    )
  }
  return (
    <span className="badge border-amber-400/30 bg-amber-400/10 text-amber-400">
      <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-current" />
      Nouvelle
    </span>
  )
}

/* ---------- Niveau de confiance d'une détection ---------- */

export function ConfidenceBadge({ value }: { value: number | null }) {
  if (value === null || value === undefined) {
    return <span className="text-xs text-slate-600">—</span>
  }
  const percent = Math.round(Math.min(1, Math.max(0, value)) * 100)
  const bar = percent >= 80 ? 'bg-red-400' : percent >= 50 ? 'bg-amber-400' : 'bg-cyan-400'
  return (
    <span className="inline-flex items-center gap-2" title={`Confiance ${percent} %`}>
      <span className="h-1.5 w-12 overflow-hidden rounded-full bg-slate-800">
        <span className={`block h-full rounded-full ${bar}`} style={{ width: `${percent}%` }} />
      </span>
      <span className="tabular-nums text-xs text-slate-400">{percent} %</span>
    </span>
  )
}

/* ---------- Score de risque (0–100) ---------- */

const RISK_LEVELS: { min: number; label: string; classes: string }[] = [
  { min: 70, label: 'critique', classes: 'border-red-400/30 bg-red-400/10 text-red-400' },
  { min: 40, label: 'élevé', classes: 'border-orange-400/30 bg-orange-400/10 text-orange-400' },
  { min: 20, label: 'modéré', classes: 'border-amber-400/30 bg-amber-400/10 text-amber-400' },
  { min: 1, label: 'faible', classes: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-400' },
]

interface RiskBadgeProps {
  score: number
  /** `sm` pour les tableaux denses (tableau de bord). */
  size?: 'md' | 'sm'
}

export function RiskBadge({ score, size = 'md' }: RiskBadgeProps) {
  const sizeClasses = size === 'sm' ? 'px-1.5 py-0 text-[10px]' : ''
  if (!score || score <= 0) {
    return (
      <span className={`badge border-slate-700 bg-slate-800 text-slate-500 ${sizeClasses}`}>
        —
      </span>
    )
  }
  const level = RISK_LEVELS.find((l) => score >= l.min) ?? RISK_LEVELS[RISK_LEVELS.length - 1]
  return (
    <span className={`badge tabular-nums ${level.classes} ${sizeClasses}`}>
      {score} · {level.label}
    </span>
  )
}
