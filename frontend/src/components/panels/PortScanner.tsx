import { useMemo, useState } from 'react'
import { ArrowDown, ArrowUp, ScanLine, ShieldAlert } from 'lucide-react'
import { Panel } from '../ui/Panel'
import { SeverityBadge } from '../ui/SeverityBadge'
import { useSocStore } from '../../store/useSocStore'
import { SEV_ORDER, classNames } from '../../lib/format'
import type { Port, Severity } from '../../lib/types'

const DANGEROUS = new Set([22, 23, 3389, 445, 21, 3306, 5432, 6379, 27017])
type SortKey = 'port' | 'service' | 'risk' | 'status'
const RISK_FILTERS: (Severity | 'all')[] = ['all', 'critical', 'high', 'medium', 'low']

export function PortScanner({ query = '' }: { query?: string }) {
  const ports = useSocStore((s) => s.ports)
  const [risk, setRisk] = useState<Severity | 'all'>('all')
  const [sort, setSort] = useState<SortKey>('risk')
  const [dir, setDir] = useState<1 | -1>(1)

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase()
    let out = ports.filter((p) => {
      if (risk !== 'all' && p.risk !== risk) return false
      if (!q) return true
      return `${p.port} ${p.service} ${p.host} ${p.protocol} ${p.status}`.toLowerCase().includes(q)
    })
    out = [...out].sort((a, b) => {
      let c = 0
      if (sort === 'port') c = a.port - b.port
      else if (sort === 'service') c = a.service.localeCompare(b.service)
      else if (sort === 'status') c = a.status.localeCompare(b.status)
      else c = SEV_ORDER[a.risk] - SEV_ORDER[b.risk]
      return c * dir
    })
    return out
  }, [ports, risk, sort, dir, query])

  const toggleSort = (k: SortKey) => {
    if (sort === k) setDir((d) => (d === 1 ? -1 : 1))
    else { setSort(k); setDir(1) }
  }

  const openCount = ports.filter((p) => p.status === 'open').length
  const dangerCount = ports.filter((p) => DANGEROUS.has(p.port) && p.status === 'open').length

  return (
    <Panel
      title="Port Scanner"
      icon={<ScanLine size={14} />}
      live
      bodyClass="flex flex-col p-0"
      actions={
        <div className="flex items-center gap-1">
          {dangerCount > 0 && (
            <span className="chip border-sev-critical/40 bg-sev-critical/10 text-sev-critical">
              <ShieldAlert size={11} /> {dangerCount} risky
            </span>
          )}
          <span className="text-[10px] text-soc-dim">{openCount} open</span>
        </div>
      }
    >
      {/* risk filter */}
      <div className="flex flex-wrap gap-1 border-b border-soc-border/70 px-3 py-2">
        {RISK_FILTERS.map((r) => (
          <button
            key={r}
            onClick={() => setRisk(r)}
            className={classNames(
              'rounded-md px-2 py-0.5 text-[11px] font-medium capitalize transition',
              risk === r ? 'bg-soc-cyan/15 text-soc-cyan' : 'text-soc-dim hover:bg-soc-panel hover:text-soc-muted',
            )}
          >
            {r}
          </button>
        ))}
      </div>

      <div className="max-h-[300px] min-h-0 flex-1 overflow-auto">
        <table className="w-full text-left text-xs">
          <thead className="sticky top-0 z-10 bg-soc-panel/95 text-[10px] uppercase tracking-wider text-soc-dim backdrop-blur">
            <tr>
              <Th label="Port" k="port" {...{ sort, dir, toggleSort }} />
              <Th label="Service" k="service" {...{ sort, dir, toggleSort }} />
              <th className="px-3 py-2 font-semibold">Proto</th>
              <Th label="Status" k="status" {...{ sort, dir, toggleSort }} />
              <Th label="Risk" k="risk" {...{ sort, dir, toggleSort }} />
              <th className="px-3 py-2 font-semibold">Host</th>
            </tr>
          </thead>
          <tbody className="font-mono">
            {rows.map((p) => <PortRow key={p.id} p={p} />)}
            {rows.length === 0 && (
              <tr><td colSpan={6} className="px-3 py-8 text-center font-sans text-soc-dim">No ports match your filters.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </Panel>
  )
}

function PortRow({ p }: { p: Port }) {
  const danger = DANGEROUS.has(p.port) && p.status === 'open'
  return (
    <tr className={classNames('border-b border-soc-border/40 transition hover:bg-soc-panel2/50', danger && 'bg-sev-critical/[0.04]')}>
      <td className="px-3 py-1.5">
        <span className={classNames('font-semibold', danger ? 'text-sev-critical' : 'text-soc-text')}>{p.port}</span>
      </td>
      <td className="px-3 py-1.5 text-soc-muted">{p.service}</td>
      <td className="px-3 py-1.5 text-soc-dim">{p.protocol}</td>
      <td className="px-3 py-1.5">
        <span className={classNames(
          'inline-flex items-center gap-1',
          p.status === 'open' ? 'text-sev-ok' : p.status === 'filtered' ? 'text-sev-medium' : 'text-soc-dim',
        )}>
          <span className="h-1.5 w-1.5 rounded-full bg-current" />{p.status}
        </span>
      </td>
      <td className="px-3 py-1.5"><SeverityBadge sev={p.risk} /></td>
      <td className="px-3 py-1.5 text-soc-dim">{p.host}</td>
    </tr>
  )
}

function Th({ label, k, sort, dir, toggleSort }: { label: string; k: SortKey; sort: SortKey; dir: 1 | -1; toggleSort: (k: SortKey) => void }) {
  const active = sort === k
  return (
    <th className="px-3 py-2 font-semibold">
      <button onClick={() => toggleSort(k)} className={classNames('flex items-center gap-1 hover:text-soc-muted', active && 'text-soc-cyan')}>
        {label}
        {active && (dir === 1 ? <ArrowUp size={11} /> : <ArrowDown size={11} />)}
      </button>
    </th>
  )
}
