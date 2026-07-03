import { useMemo } from 'react'
import { Bug, ShieldCheck, Wrench } from 'lucide-react'
import { Panel } from '../ui/Panel'
import { SeverityBadge } from '../ui/SeverityBadge'
import { useSocStore } from '../../store/useSocStore'
import { SEV, SEV_ORDER, classNames } from '../../lib/format'
import type { Vulnerability } from '../../lib/types'

export function VulnScanner({ query = '' }: { query?: string }) {
  const vulns = useSocStore((s) => s.vulns)

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase()
    return [...vulns]
      .filter((v) => !q || `${v.id} ${v.service} ${v.title}`.toLowerCase().includes(q))
      .sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || b.cvss - a.cvss)
  }, [vulns, query])

  const crit = vulns.filter((v) => v.severity === 'critical').length

  return (
    <Panel
      title="Vulnerability Scanner"
      icon={<Bug size={14} />}
      actions={
        crit > 0
          ? <span className="chip border-sev-critical/40 bg-sev-critical/10 text-sev-critical">{crit} critical</span>
          : <span className="chip border-sev-ok/40 bg-sev-ok/10 text-sev-ok"><ShieldCheck size={11} /> clear</span>
      }
      bodyClass="p-3"
    >
      <div className="grid max-h-[320px] grid-cols-1 gap-2.5 overflow-y-auto pr-1">
        {rows.map((v) => <VulnCard key={v.id} v={v} />)}
        {rows.length === 0 && <div className="py-8 text-center text-sm text-soc-dim">No vulnerabilities match.</div>}
      </div>
    </Panel>
  )
}

function VulnCard({ v }: { v: Vulnerability }) {
  const c = SEV[v.severity].hex
  return (
    <article
      className={classNames('rounded-lg border bg-soc-panel2/40 p-3 transition hover:border-soc-borderlit', SEV[v.severity].border)}
      style={{ boxShadow: v.severity === 'critical' ? `inset 3px 0 0 ${c}` : `inset 3px 0 0 ${c}88` }}
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-xs font-bold text-soc-text">{v.id}</span>
        <SeverityBadge sev={v.severity} />
        <span className="chip border-soc-border bg-soc-panel text-soc-muted tnum">CVSS {v.cvss.toFixed(1)}</span>
        <span className="ml-auto font-mono text-[10px] text-soc-dim">{v.service}</span>
      </div>
      <h4 className="mt-1.5 text-sm font-semibold text-soc-text">{v.title}</h4>
      <p className="mt-0.5 text-xs leading-relaxed text-soc-muted">{v.description}</p>
      <div className="mt-2 flex items-start gap-1.5 rounded-md border border-soc-border/60 bg-soc-bg/40 px-2 py-1.5 text-[11px] text-soc-muted">
        <Wrench size={12} className="mt-0.5 shrink-0 text-sev-ok" />
        <span><span className="font-semibold text-sev-ok">Fix:</span> {v.remediation}</span>
      </div>
    </article>
  )
}
