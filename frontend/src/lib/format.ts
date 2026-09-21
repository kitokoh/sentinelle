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

/** « il y a 3 min » — plus parlant qu'un horodatage dans un flux d'alertes. */
export function formatRelativeTime(value: string | null | undefined): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value

  const seconds = Math.round((date.getTime() - Date.now()) / 1000)
  const formatter = new Intl.RelativeTimeFormat('fr-FR', { numeric: 'auto' })
  const steps: [Intl.RelativeTimeFormatUnit, number][] = [
    ['second', 60],
    ['minute', 60],
    ['hour', 24],
    ['day', 7],
    ['week', 4.35],
    ['month', 12],
    ['year', Number.POSITIVE_INFINITY],
  ]

  let amount = seconds
  for (const [unit, size] of steps) {
    if (Math.abs(amount) < size) return formatter.format(Math.round(amount), unit)
    amount /= size
  }
  return formatter.format(Math.round(amount), 'year')
}

/** 0.625 -> « 63 % » (confiance d'une détection). */
export function formatConfidence(value: number | null | undefined): string {
  if (value === null || value === undefined) return '—'
  return `${Math.round(value * 100)} %`
}
