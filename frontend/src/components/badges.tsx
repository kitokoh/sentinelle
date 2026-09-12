import { ShieldAlert, ShieldCheck } from 'lucide-react'
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
