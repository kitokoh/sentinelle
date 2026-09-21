import type { LucideIcon } from 'lucide-react'

type Tone = 'cyan' | 'emerald' | 'red' | 'amber' | 'slate'

const TONE_CLASSES: Record<Tone, string> = {
  cyan: 'border-cyan-400/20 text-cyan-400',
  emerald: 'border-emerald-400/20 text-emerald-400',
  red: 'border-red-400/20 text-red-400',
  amber: 'border-amber-400/20 text-amber-400',
  slate: 'border-slate-700 text-slate-400',
}

interface StatCardProps {
  label: string
  value: string | number
  icon: LucideIcon
  tone?: Tone
  hint?: string
}

export default function StatCard({ label, value, icon: Icon, tone = 'cyan', hint }: StatCardProps) {
  return (
    <div className="panel flex items-start justify-between p-5">
      <div>
        <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">{label}</p>
        <p className="mt-2 text-3xl font-semibold tabular-nums text-slate-100">{value}</p>
        {hint ? <p className="mt-1 text-xs text-slate-500">{hint}</p> : null}
      </div>
      <div className={`rounded-md border p-2 ${TONE_CLASSES[tone]}`}>
        <Icon className="h-5 w-5" />
      </div>
    </div>
  )
}
