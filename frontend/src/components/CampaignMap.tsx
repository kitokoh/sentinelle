import { CircleMarker, MapContainer, Popup, TileLayer } from 'react-leaflet'
import 'leaflet/dist/leaflet.css'
import type { GeoPoint } from '../lib/types'

/** Couleur par sévérité — cohérente avec les pastilles du reste de l'interface. */
const SEVERITY_COLORS: Record<string, string> = {
  critical: '#f87171',
  high: '#fb923c',
  medium: '#fbbf24',
  low: '#22d3ee',
  info: '#94a3b8',
}

interface CampaignMapProps {
  points: GeoPoint[]
}

/**
 * Carte des campagnes (react-leaflet, tuiles OpenStreetMap).
 *
 * Seuls les indicateurs pour lesquels un flux a **fourni** des coordonnées sont
 * affichés : aucun indicateur n'est envoyé à un service de géolocalisation pour
 * être placé sur la carte. Des marqueurs circulaires sont utilisés plutôt que
 * les épingles par défaut de Leaflet, dont les images se chargent mal derrière
 * un bundler.
 */
export default function CampaignMap({ points }: CampaignMapProps) {
  const withCoordinates = points.filter(
    (point) => Number.isFinite(point.latitude) && Number.isFinite(point.longitude),
  )

  if (withCoordinates.length === 0) {
    return (
      <div className="flex h-[360px] flex-col items-center justify-center gap-2 px-6 text-center">
        <p className="text-sm text-slate-400">Aucune coordonnée fournie par les flux</p>
        <p className="max-w-md text-xs text-slate-600">
          La carte n'affiche que les indicateurs géolocalisés à la source (MISP, OTX). Aucun
          indicateur n'est transmis à un service tiers pour être positionné.
        </p>
      </div>
    )
  }

  const latitudes = withCoordinates.map((point) => point.latitude)
  const longitudes = withCoordinates.map((point) => point.longitude)
  const center: [number, number] = [
    latitudes.reduce((total, value) => total + value, 0) / latitudes.length,
    longitudes.reduce((total, value) => total + value, 0) / longitudes.length,
  ]

  return (
    <div className="h-[360px] w-full overflow-hidden rounded-b-lg">
      <MapContainer
        center={center}
        zoom={withCoordinates.length === 1 ? 5 : 2}
        scrollWheelZoom={false}
        style={{ height: '100%', width: '100%', background: '#020617' }}
      >
        <TileLayer
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
        />
        {withCoordinates.map((point) => (
          <CircleMarker
            key={`${point.type}-${point.label}-${point.latitude}-${point.longitude}`}
            center={[point.latitude, point.longitude]}
            radius={8}
            pathOptions={{
              color: SEVERITY_COLORS[point.severity] ?? SEVERITY_COLORS.info,
              fillColor: SEVERITY_COLORS[point.severity] ?? SEVERITY_COLORS.info,
              fillOpacity: 0.55,
              weight: 2,
            }}
          >
            <Popup>
              <span className="font-mono text-xs">{point.label}</span>
              <br />
              <span className="text-xs">{point.type}</span>
              {point.name ? (
                <>
                  <br />
                  <span className="text-xs">{point.name}</span>
                </>
              ) : null}
              <br />
              <span className="text-xs">sources : {point.sources}</span>
            </Popup>
          </CircleMarker>
        ))}
      </MapContainer>
    </div>
  )
}
