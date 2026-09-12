import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'

interface EmptyStateProps {
  icon: LucideIcon
  title: string
  description?: string
  children?: ReactNode
}

export default function EmptyState({ icon: Icon, title, description, children }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-12 text-center">
      <Icon className="h-6 w-6 text-slate-600" />
      <p className="mt-3 text-sm font-medium text-slate-400">{title}</p>
      {description ? <p className="mt-1 max-w-sm text-xs text-slate-600">{description}</p> : null}
      {children}
    </div>
  )
}
