import { AlertTriangle, DoorOpen, HeartPulse, KeyRound, MonitorSmartphone, ShieldAlert } from 'lucide-react'
import { StatCard } from '../ui/StatCard'
import { useSocStore } from '../../store/useSocStore'

// Top strip of live KPIs. Sparklines are derived from the rolling timeline.
export function SummaryBar() {
  const stats = useSocStore((s) => s.stats)
  const timeline = useSocStore((s) => s.timeline)
  if (!stats) return <SummarySkeleton />

  const series = (key: 'logins' | 'scans' | 'suspicious' | 'blocked') => timeline.slice(-16).map((t) => t[key])

  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
      <StatCard label="Threats Today" value={stats.threatsToday} icon={<ShieldAlert size={18} />} accent="#F43F5E" danger trend={series('suspicious')} />
      <StatCard label="Open Ports" value={stats.openPorts} icon={<DoorOpen size={18} />} accent="#FB923C" />
      <StatCard label="Suspicious IPs" value={stats.suspiciousIps} icon={<AlertTriangle size={18} />} accent="#FACC15" trend={series('scans')} />
      <StatCard label="Failed Logins" value={stats.failedLogins} icon={<KeyRound size={18} />} accent="#8B5CF6" trend={series('logins')} />
      <StatCard label="Active Devices" value={stats.activeDevices} icon={<MonitorSmartphone size={18} />} accent="#22D3EE" />
      <StatCard label="System Health" value={stats.healthScore} suffix="/100" icon={<HeartPulse size={18} />} accent="#34D399" trend={series('blocked')} />
    </div>
  )
}

function SummarySkeleton() {
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
      {Array.from({ length: 6 }).map((_, i) => (
        <div key={i} className="panel h-[86px] animate-pulse bg-soc-panel/40" />
      ))}
    </div>
  )
}
