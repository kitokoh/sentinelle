import { AlertTriangle, Loader2 } from 'lucide-react'

/** Indicateur de chargement sobre, utilisé dans les panneaux. */
export function LoadingState({ label = 'Chargement…' }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 px-6 py-12 text-sm text-slate-500">
      <Loader2 className="h-4 w-4 animate-spin" />
      {label}
    </div>
  )
}

/** Bloc d'erreur avec possibilité de relancer la requête. */
export function ErrorState({
  message,
  onRetry,
}: {
  message: string
  onRetry?: () => void
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-12 text-center">
      <AlertTriangle className="h-6 w-6 text-red-400" />
      <p className="max-w-md text-sm text-slate-400">{message}</p>
      {onRetry ? (
        <button type="button" className="btn-ghost" onClick={onRetry}>
          Réessayer
        </button>
      ) : null}
    </div>
  )
}
