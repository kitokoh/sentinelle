import { FileText } from 'lucide-react'
import PageHeader from '../components/PageHeader'

export default function ReportsPage() {
  return (
    <div>
      <PageHeader
        title="Rapports"
        description="Comptes rendus d'audit consolidés, prêts pour diffusion."
      />

      <div className="panel flex flex-col items-center border-dashed px-6 py-20 text-center">
        <div className="rounded-full border border-slate-700 p-4 text-slate-500">
          <FileText className="h-8 w-8" />
        </div>
        <h2 className="mt-6 text-lg font-semibold text-slate-200">
          Génération de rapports PDF — v0.5 (voir roadmap)
        </h2>
        <p className="mt-2 max-w-md text-sm leading-relaxed text-slate-500">
          Les rapports d'audit consolidés — périmètre, constats, criticité et recommandations —
          seront générés ici au format PDF, horodatés et signés pour diffusion officielle.
        </p>
        <span className="badge mt-6 border-slate-700 bg-slate-800/60 text-slate-400">
          Bientôt disponible
        </span>
      </div>
    </div>
  )
}
