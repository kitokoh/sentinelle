import {
  Flag,
  Globe,
  GraduationCap,
  Landmark,
  ShieldCheck,
  type LucideIcon,
} from 'lucide-react'
import PageHeader from '../components/PageHeader'

interface Pillar {
  icon: LucideIcon
  title: string
  text: string
  points: string[]
}

const PILLARS: Pillar[] = [
  {
    icon: Landmark,
    title: 'Gouvernance',
    text: "Une chaîne de commandement claire et un pilotage interministériel, appuyés sur un cadre juridique adapté aux opérations dans le cyberespace.",
    points: [
      'Comité interministériel de la cyberdéfense',
      "Doctrine d'emploi des capacités défensives",
      'Cadre juridique et contrôle parlementaire',
    ],
  },
  {
    icon: ShieldCheck,
    title: 'Protection des infrastructures critiques',
    text: "Identifier, durcir et superviser en continu les systèmes d'information des opérateurs d'importance vitale.",
    points: [
      'Audits de sécurité obligatoires et pentests encadrés',
      'Détection et réponse à incident 24/7',
      'Plans de continuité et de reprise éprouvés',
    ],
  },
  {
    icon: Flag,
    title: 'Souveraineté numérique',
    text: "Garantir l'autonomie stratégique de l'État : technologies de confiance, hébergement souverain et maîtrise des chaînes d'approvisionnement.",
    points: [
      'Cloud souverain et chiffrement maîtrisé',
      'Qualification nationale des produits de sécurité',
      'Réduction des dépendances technologiques critiques',
    ],
  },
  {
    icon: GraduationCap,
    title: 'Talents & formation',
    text: "Constituer, former et fidéliser une réserve d'experts capable de faire face à la montée en puissance des menaces.",
    points: [
      'Académies cyber et cursus spécialisés',
      'Réserve citoyenne de cyberdéfense',
      'Certification continue des analystes',
    ],
  },
  {
    icon: Globe,
    title: 'Coopération internationale',
    text: 'La menace est transnationale : partager le renseignement, coordonner la réponse et exercer ensemble les forces alliées.',
    points: [
      "Échange d'indicateurs de compromission",
      'Exercices conjoints et clauses d’assistance mutuelle',
      'Promotion du droit international dans le cyberespace',
    ],
  },
]

export default function DoctrinePage() {
  return (
    <div>
      <PageHeader
        title="Doctrine"
        description="Les cinq piliers du cadre stratégique national de cyber-défense appliqués par Sentinelle."
      />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
        {PILLARS.map((pillar, index) => (
          <article
            key={pillar.title}
            className="panel group flex flex-col p-6 transition-colors hover:border-cyan-400/30"
          >
            <div className="flex items-center justify-between">
              <div className="rounded-md border border-cyan-400/20 p-2 text-cyan-400">
                <pillar.icon className="h-5 w-5" />
              </div>
              <span className="font-mono text-xs text-slate-600">
                {String(index + 1).padStart(2, '0')}
              </span>
            </div>

            <h2 className="mt-4 text-base font-semibold text-slate-100">{pillar.title}</h2>
            <p className="mt-2 text-sm leading-relaxed text-slate-400">{pillar.text}</p>

            <ul className="mt-4 space-y-2 border-t border-slate-800 pt-4">
              {pillar.points.map((point) => (
                <li key={point} className="flex items-start gap-2 text-xs text-slate-500">
                  <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-cyan-400" />
                  {point}
                </li>
              ))}
            </ul>
          </article>
        ))}

        {/* Carte de synthèse */}
        <article className="panel flex flex-col justify-between border-cyan-400/20 bg-cyan-400/5 p-6">
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-cyan-400/80">
              Sentinelle · Référentiel
            </p>
            <h2 className="mt-4 text-base font-semibold text-slate-100">
              Défendre en amont, réagir sans délai
            </h2>
            <p className="mt-2 text-sm leading-relaxed text-slate-400">
              La plateforme opère exclusivement dans le respect de ces piliers : scans autorisés,
              traçabilité complète des campagnes et restitution opposable des constats.
            </p>
          </div>
          <p className="mt-6 border-t border-cyan-400/10 pt-4 text-xs text-slate-500">
            Document de référence — révision 2026.1 · diffusion restreinte
          </p>
        </article>
      </div>
    </div>
  )
}
