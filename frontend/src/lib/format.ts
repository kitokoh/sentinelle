/** Formatage date/heure au format français ; renvoie '—' si la valeur est absente. */
export function formatDateTime(value: string | null | undefined): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return new Intl.DateTimeFormat('fr-FR', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date)
}

/** Formatage numérique fr-FR (espaces insécables comme séparateurs de milliers). */
export function formatNumber(value: number | null | undefined): string {
  return (value ?? 0).toLocaleString('fr-FR')
}

export const PROFILE_LABELS: Record<string, string> = {
  quick: 'Rapide',
  full: 'Complet',
}

export const KIND_LABELS: Record<string, string> = {
  ip: 'IP',
  hostname: "Nom d'hôte",
  cidr: 'CIDR',
}
