import { Gauge, ShieldCheck, ShieldAlert, Cpu } from 'lucide-react'
import { Panel } from '../ui/Panel'
import { ThreatGauge } from '../ui/ThreatGauge'
import { useSocStore } from '../../store/useSocStore'
import { SEV } from '../../lib/format'
import type { Severity } from '../../lib/types'

// Security posture at a glance: the radial threat score + a live severity
// breakdown compiled from ports, vulns and alerts.
export function OverviewPanel() {
  const { stats, ports, vulns, alerts, devices } = useSocStore()

  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, ok: 0 }
  ports.forEach((p) => p.status === 'open' && counts[p.risk]++)
  vulns.forEach((v) => counts[v.severity]++)
  alerts.forEach((a) => counts[a.severity]++)

  const bars: { sev: Severity; label: string }[] = [
    { sev: 'critical', label: 'Critical' },
    { sev: 'high', label: 'High' },
    { sev: 'medium', label: 'Medium' },
    { sev: 'low', label: 'Low' },
  ]
  const max = Math.max(1, ...bars.map((b) => counts[b.sev]))

  return (
    <Panel title="Security Posture" icon={<Gauge size={14} />} live>
      <div className="flex flex-col items-center">
        <ThreatGauge score={stats?.threatScore ?? 0} />
        <div className="mt-2 grid w-full grid-cols-2 gap-2 text-center">
          <Metric icon={<ShieldCheck size={13} />} label="Health" value={`${stats?.healthScore ?? 0}/100`} tone="#34D399" />
          <Metric icon={<Cpu size={13} />} label="Devices" value={String(devices.length)} tone="#22D3EE" />
        </div>
      </div>

      <div className="mt-4 space-y-2">
        <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-soc-dim">
          <ShieldAlert size={12} /> Severity breakdown
        </div>
        {bars.map((b) => (
          <div key={b.sev} className="flex items-center gap-2 text-xs">
            <span className="w-14 text-soc-muted">{b.label}</span>
            <div className="h-2 flex-1 overflow-hidden rounded-full bg-soc-panel">
              <div className="h-full rounded-full transition-all duration-500" style={{ width: `${(counts[b.sev] / max) * 100}%`, background: SEV[b.sev].hex, boxShadow: `0 0 8px ${SEV[b.sev].hex}88` }} />
            </div>
            <span className="tnum w-6 text-right font-mono text-soc-muted">{counts[b.sev]}</span>
          </div>
        ))}
      </div>
    </Panel>
  )
}

function Metric({ icon, label, value, tone }: { icon: React.ReactNode; label: string; value: string; tone: string }) {
  return (
    <div className="rounded-lg border border-soc-border bg-soc-panel2/40 py-2">
      <div className="flex items-center justify-center gap-1 text-[10px] uppercase tracking-wider text-soc-dim" style={{ color: tone }}>
        {icon} {label}
      </div>
      <div className="tnum mt-0.5 text-sm font-bold text-soc-text">{value}</div>
    </div>
  )
}
