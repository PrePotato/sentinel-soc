import { useEffect, useState } from 'react'
import { LogOut, Menu, Pause, Play, RadioTower, RefreshCw, Search, Volume2, VolumeX, Wifi } from 'lucide-react'
import { useSocStore } from '../../store/useSocStore'
import { useAuthStore } from '../../store/useAuthStore'
import { useManualScan } from '../../hooks/useLiveFeed'
import { classNames } from '../../lib/format'

export function Topbar({ onMenu, query, setQuery }: { onMenu: () => void; query: string; setQuery: (v: string) => void }) {
  const { connected, simMode, paused, soundOn, scanning, togglePause, toggleSound } = useSocStore()
  const user = useAuthStore((s) => s.user)
  const logout = useAuthStore((s) => s.logout)
  const scan = useManualScan()
  const [now, setNow] = useState(() => new Date())

  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(t)
  }, [])

  return (
    <header className="sticky top-0 z-20 flex items-center gap-3 border-b border-soc-border bg-soc-bg/80 px-3 py-2.5 backdrop-blur-md sm:px-4">
      <button className="text-soc-muted hover:text-soc-text lg:hidden" onClick={onMenu} aria-label="Open menu">
        <Menu size={20} />
      </button>

      {/* Live/Sim status pill */}
      <div
        className={classNames(
          'hidden items-center gap-1.5 rounded-md border px-2.5 py-1 text-[11px] font-semibold sm:flex',
          connected ? 'border-sev-ok/40 bg-sev-ok/10 text-sev-ok' : 'border-soc-cyan/40 bg-soc-cyan/10 text-soc-cyan',
        )}
        title={connected ? 'Connected to backend engine' : 'Backend offline — running simulated telemetry'}
      >
        {connected ? <Wifi size={13} /> : <RadioTower size={13} />}
        {connected ? 'LIVE' : simMode ? 'SIMULATION' : 'CONNECTING'}
        <span className={classNames('h-1.5 w-1.5 rounded-full', connected ? 'bg-sev-ok' : 'bg-soc-cyan', 'animate-pulse')} />
      </div>

      {/* Global search */}
      <div className="relative flex-1 max-w-md">
        <Search size={15} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-soc-dim" />
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search IPs, devices, ports, CVEs, events…"
          className="w-full rounded-md border border-soc-border bg-soc-panel/60 py-1.5 pl-8 pr-3 text-sm text-soc-text placeholder:text-soc-dim focus:border-soc-cyan/60 focus:outline-none focus:ring-1 focus:ring-soc-cyan/40"
        />
      </div>

      <div className="ml-auto flex items-center gap-1.5">
        <button
          onClick={scan}
          className="flex items-center gap-1.5 rounded-md border border-soc-cyan/40 bg-soc-cyan/10 px-2.5 py-1.5 text-xs font-semibold text-soc-cyan transition hover:bg-soc-cyan/20"
          title="Run a manual scan"
        >
          <RefreshCw size={14} className={scanning ? 'animate-spin' : ''} />
          <span className="hidden sm:inline">{scanning ? 'Scanning…' : 'Scan'}</span>
        </button>

        <IconBtn on={!paused} onClick={togglePause} title={paused ? 'Resume feed' : 'Pause feed'}>
          {paused ? <Play size={16} /> : <Pause size={16} />}
        </IconBtn>
        <IconBtn on={soundOn} onClick={toggleSound} title={soundOn ? 'Mute alerts' : 'Enable alert sounds'}>
          {soundOn ? <Volume2 size={16} /> : <VolumeX size={16} />}
        </IconBtn>

        <div className="mx-1 hidden font-mono text-xs tabular-nums text-soc-muted md:block">
          {now.toLocaleTimeString('en-GB', { hour12: false })}
        </div>

        <div className="flex items-center gap-2 rounded-md border border-soc-border bg-soc-panel/60 py-1 pl-2 pr-1">
          <div className="hidden text-right sm:block">
            <div className="text-xs font-semibold leading-none text-soc-text">{user?.username ?? 'guest'}</div>
            <div className="text-[10px] uppercase tracking-wider text-soc-dim">{user?.role ?? 'viewer'}</div>
          </div>
          <div className="grid h-6 w-6 place-items-center rounded bg-soc-cyan/15 text-[11px] font-bold uppercase text-soc-cyan">
            {(user?.username ?? 'g')[0]}
          </div>
          <button onClick={logout} className="text-soc-dim hover:text-sev-critical" title="Log out" aria-label="Log out">
            <LogOut size={15} />
          </button>
        </div>
      </div>
    </header>
  )
}

function IconBtn({ on, onClick, title, children }: { on: boolean; onClick: () => void; title: string; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      title={title}
      aria-label={title}
      className={classNames(
        'grid h-8 w-8 place-items-center rounded-md border transition',
        on ? 'border-soc-border bg-soc-panel/60 text-soc-muted hover:text-soc-text' : 'border-soc-border bg-soc-panel/30 text-soc-dim hover:text-soc-muted',
      )}
    >
      {children}
    </button>
  )
}
