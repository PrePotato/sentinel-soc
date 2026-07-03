import { useEffect, useState } from 'react'
import {
  Activity, Bell, Bot, Bug, FileText, Globe, LayoutDashboard,
  Network, ScanLine, Shield, Terminal, X,
} from 'lucide-react'
import { classNames } from '../../lib/format'
import { useSocStore } from '../../store/useSocStore'

const NAV = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'network', label: 'Network Map', icon: Network },
  { id: 'ports', label: 'Port Scanner', icon: ScanLine },
  { id: 'timeline', label: 'Threat Timeline', icon: Activity },
  { id: 'packets', label: 'Packet Feed', icon: Terminal },
  { id: 'vulns', label: 'Vulnerabilities', icon: Bug },
  { id: 'geo', label: 'Geo Attacks', icon: Globe },
  { id: 'alerts', label: 'Alerts', icon: Bell },
  { id: 'ai', label: 'AI Analyst', icon: Bot },
  { id: 'reports', label: 'Reports', icon: FileText },
]

export function Sidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [active, setActive] = useState('overview')
  const alerts = useSocStore((s) => s.alerts)
  const openAlerts = alerts.filter((a) => !a.ack).length

  // Highlight the section currently in view.
  useEffect(() => {
    const obs = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => e.isIntersecting && setActive(e.target.id))
      },
      { rootMargin: '-45% 0px -50% 0px' },
    )
    NAV.forEach((n) => {
      const el = document.getElementById(n.id)
      if (el) obs.observe(el)
    })
    return () => obs.disconnect()
  }, [])

  const go = (id: string) => {
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    onClose()
  }

  return (
    <>
      {open && <div className="fixed inset-0 z-30 bg-black/60 backdrop-blur-sm lg:hidden" onClick={onClose} />}
      <aside
        className={classNames(
          'fixed inset-y-0 left-0 z-40 flex w-60 flex-col border-r border-soc-border bg-soc-bg2/95 backdrop-blur-md transition-transform lg:static lg:z-0 lg:translate-x-0',
          open ? 'translate-x-0' : '-translate-x-full',
        )}
      >
        <div className="flex items-center gap-2.5 px-4 py-4">
          <div className="grid h-9 w-9 place-items-center rounded-lg border border-soc-cyan/40 bg-soc-cyan/10 shadow-glow-cyan">
            <Shield size={18} className="text-soc-cyan" />
          </div>
          <div>
            <div className="text-sm font-bold tracking-wide text-soc-text">
              SENTINEL<span className="text-soc-cyan glow-text-cyan"> SOC</span>
            </div>
            <div className="text-[10px] uppercase tracking-[0.18em] text-soc-dim">Threat Operations</div>
          </div>
          <button className="ml-auto text-soc-dim hover:text-soc-text lg:hidden" onClick={onClose} aria-label="Close menu">
            <X size={18} />
          </button>
        </div>

        <nav className="flex-1 space-y-0.5 overflow-y-auto px-2.5 py-2">
          {NAV.map((n) => {
            const Icon = n.icon
            const on = active === n.id
            return (
              <button
                key={n.id}
                onClick={() => go(n.id)}
                className={classNames(
                  'group flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-all',
                  on ? 'bg-soc-cyan/10 text-soc-text' : 'text-soc-muted hover:bg-soc-panel hover:text-soc-text',
                )}
              >
                <span className={classNames('h-4 w-0.5 rounded-full transition-all', on ? 'bg-soc-cyan shadow-glow-cyan' : 'bg-transparent')} />
                <Icon size={17} className={on ? 'text-soc-cyan' : 'text-soc-dim group-hover:text-soc-muted'} />
                <span>{n.label}</span>
                {n.id === 'alerts' && openAlerts > 0 && (
                  <span className="tnum ml-auto rounded-full bg-sev-critical/20 px-1.5 py-0.5 text-[10px] font-bold text-sev-critical">
                    {openAlerts}
                  </span>
                )}
              </button>
            )
          })}
        </nav>

        <div className="border-t border-soc-border px-4 py-3 text-[10px] text-soc-dim">
          <div className="flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-sev-ok" />
            Engine online · v1.0
          </div>
        </div>
      </aside>
    </>
  )
}
