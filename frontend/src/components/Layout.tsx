import { NavLink, Outlet, useLocation } from 'react-router-dom'
import {
  Crosshair,
  FileText,
  Globe2,
  History,
  Landmark,
  LayoutDashboard,
  LogOut,
  Radar,
  Shield,
  Siren,
} from 'lucide-react'
import { useAuth } from '../auth/AuthContext'
import { useAlertStats } from '../lib/alerts'
import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'
import type { Organization } from '../lib/types'

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/cibles', label: 'Cibles', icon: Crosshair, end: false },
  { to: '/scans', label: 'Scans', icon: Radar, end: false },
  { to: '/alertes', label: 'Alertes', icon: Siren, end: false },
  { to: '/renseignement', label: 'Renseignement', icon: Globe2, end: false },
  { to: '/rapports', label: 'Rapports', icon: FileText, end: false },
  { to: '/doctrine', label: 'Doctrine', icon: Landmark, end: false },
] as const

/** Réservé aux administrateurs — l'API refuse de toute façon l'accès aux autres rôles. */
const ADMIN_NAV_ITEMS = [
  { to: '/journal', label: "Journal d'audit", icon: History, end: false },
] as const

function currentSection(pathname: string): string {
  if (pathname.startsWith('/cibles')) return 'Cibles'
  if (pathname.startsWith('/scans')) return 'Scans'
  if (pathname.startsWith('/alertes')) return 'Alertes'
  if (pathname.startsWith('/renseignement')) return 'Renseignement'
  if (pathname.startsWith('/rapports')) return 'Rapports'
  if (pathname.startsWith('/doctrine')) return 'Doctrine'
  if (pathname.startsWith('/journal')) return "Journal d'audit"
  return 'Dashboard'
}

export default function Layout() {
  const { user, logout } = useAuth()
  const location = useLocation()
  const initial = (user?.email ?? '·').charAt(0).toUpperCase()
  // Compteur d'alertes non acquittées — rafraîchi par la même requête que la page.
  const { data: alertStats } = useAlertStats()
  const unacknowledged = alertStats?.unacknowledged ?? 0
  const isAdmin = user?.role === 'admin'
  // L'organisation n'est affichée que si elle est connue : pas de squelette inutile.
  const { data: organization } = useQuery({
    queryKey: ['organization'],
    queryFn: async (): Promise<Organization> => {
      const { data } = await api.get<Organization>('/users/organization')
      return data
    },
    enabled: user !== null,
    staleTime: 5 * 60_000,
  })

  return (
    <div className="min-h-screen bg-slate-950">
      {/* Barre latérale */}
      <aside className="fixed inset-y-0 left-0 flex w-64 flex-col border-r border-slate-800 bg-slate-900">
        <div className="flex h-16 items-center gap-3 border-b border-slate-800 px-5">
          <div className="rounded-md border border-cyan-400/30 p-2 text-cyan-400">
            <Shield className="h-5 w-5" />
          </div>
          <div>
            <p className="text-sm font-bold tracking-[0.2em] text-slate-100">SENTINELLE</p>
            <p className="text-[10px] uppercase tracking-wider text-slate-500">
              Cyber-défense · SOC
            </p>
          </div>
        </div>

        <nav className="flex-1 space-y-1 px-3 py-4">
          {[...NAV_ITEMS, ...(isAdmin ? ADMIN_NAV_ITEMS : [])].map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors ${
                  isActive
                    ? 'bg-slate-800 font-medium text-cyan-400'
                    : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
                }`
              }
            >
              <Icon className="h-4 w-4" />
              {label}
              {to === '/alertes' && unacknowledged > 0 ? (
                <span
                  className="ml-auto rounded-full border border-amber-400/30 bg-amber-400/10 px-1.5 py-0.5 text-[10px] font-semibold tabular-nums text-amber-400"
                  title={`${unacknowledged} alerte(s) non acquittée(s)`}
                >
                  {unacknowledged}
                </span>
              ) : null}
            </NavLink>
          ))}
        </nav>

        <div className="border-t border-slate-800 px-5 py-4">
          <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-amber-400/70">
            Diffusion restreinte
          </p>
          <p className="mt-1 text-xs text-slate-600">
            {organization ? organization.name : 'Sentinelle'} · v0.5
          </p>
        </div>
      </aside>

      {/* Colonne principale */}
      <div className="ml-64 flex min-h-screen flex-col">
        <header className="sticky top-0 z-10 flex h-16 items-center justify-between border-b border-slate-800 bg-slate-950/90 px-8 backdrop-blur">
          <div className="flex items-center gap-2 text-sm">
            <span className="font-mono text-xs uppercase tracking-wider text-slate-600">
              Sentinelle
            </span>
            <span className="text-slate-700">/</span>
            <span className="text-slate-300">{currentSection(location.pathname)}</span>
          </div>

          <div className="flex items-center gap-4">
            <span className="hidden items-center gap-2 text-xs text-slate-500 md:flex">
              <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
              SOC opérationnel
            </span>

            <div className="flex items-center gap-2.5 border-l border-slate-800 pl-4">
              <div className="flex h-8 w-8 items-center justify-center rounded-full border border-slate-700 bg-slate-800 text-xs font-semibold text-cyan-400">
                {initial}
              </div>
              <div className="hidden sm:block">
                <p className="max-w-[180px] truncate text-xs font-medium text-slate-300">
                  {user?.email ?? '…'}
                </p>
                <p className="text-[10px] uppercase tracking-wider text-slate-500">
                  {user?.role ?? ''}
                </p>
              </div>
              <button
                type="button"
                onClick={logout}
                title="Déconnexion"
                className="ml-2 rounded-md p-2 text-slate-500 transition-colors hover:bg-slate-800 hover:text-red-400"
              >
                <LogOut className="h-4 w-4" />
              </button>
            </div>
          </div>
        </header>

        <main className="flex-1 px-8 py-8">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
