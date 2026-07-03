import { Bell, Check, CheckCheck, ChevronRight, Crosshair } from 'lucide-react'
import { Panel } from '../ui/Panel'
import { useSocStore } from '../../store/useSocStore'
import { SEV, classNames, timeAgo } from '../../lib/format'
import type { Alert } from '../../lib/types'

export function AlertsPanel() {
  const alerts = useSocStore((s) => s.alerts)
  const ackAlert = useSocStore((s) => s.ackAlert)
  const clearAlerts = useSocStore((s) => s.clearAlerts)
  const openCount = alerts.filter((a) => !a.ack).length

  return (
    <Panel
      title="Alert Center"
      icon={<Bell size={14} />}
      live
      bodyClass="p-0"
      actions={
        <div className="flex items-center gap-2">
          {openCount > 0 && <span className="chip border-sev-critical/40 bg-sev-critical/10 text-sev-critical tnum">{openCount} open</span>}
          {alerts.length > 0 && (
            <button onClick={clearAlerts} className="flex items-center gap-1 text-[10px] text-soc-dim hover:text-soc-muted" title="Clear all">
              <CheckCheck size={12} /> clear
            </button>
          )}
        </div>
      }
    >
      <div className="max-h-[340px] min-h-[200px] overflow-y-auto">
        {alerts.length === 0 && (
          <div className="grid h-[200px] place-items-center text-sm text-soc-dim">
            <div className="text-center">
              <Check size={22} className="mx-auto mb-1 text-sev-ok" />
              No active alerts. All clear.
            </div>
          </div>
        )}
        <ul className="divide-y divide-soc-border/40">
          {alerts.map((a) => <AlertRow key={a.id} a={a} onAck={() => ackAlert(a.id)} />)}
        </ul>
      </div>
    </Panel>
  )
}

function AlertRow({ a, onAck }: { a: Alert; onAck: () => void }) {
  const c = SEV[a.severity].hex
  return (
    <li
      className={classNames('group flex animate-fade-up gap-3 px-3 py-2.5 transition hover:bg-soc-panel2/40', a.ack && 'opacity-45')}
      style={{ boxShadow: `inset 3px 0 0 ${c}` }}
    >
      <div className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-md" style={{ background: c + '18', color: c }}>
        <Bell size={13} />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-soc-text">{a.type}</span>
          <span className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: c }}>{a.severity}</span>
          <span className="ml-auto shrink-0 font-mono text-[10px] text-soc-dim">{timeAgo(a.ts)}</span>
        </div>
        <p className="mt-0.5 text-xs leading-snug text-soc-muted">{a.message}</p>
        {a.technique && (
          <div className="mt-1 inline-flex items-center gap-1 rounded border border-soc-border/60 bg-soc-bg/40 px-1.5 py-0.5 font-mono text-[10px] text-soc-muted">
            <Crosshair size={10} className="text-soc-violet" />{a.technique}
          </div>
        )}
        <div className="mt-1 flex items-center gap-1 text-[11px] text-soc-dim">
          <ChevronRight size={11} className="text-sev-ok" />
          <span className="truncate"><span className="text-sev-ok">Action:</span> {a.action}</span>
        </div>
      </div>
      {!a.ack && (
        <button
          onClick={onAck}
          className="self-center rounded-md border border-soc-border bg-soc-panel/60 px-2 py-1 text-[10px] font-medium text-soc-muted opacity-0 transition hover:border-sev-ok/40 hover:text-sev-ok group-hover:opacity-100"
          title="Acknowledge"
        >
          Ack
        </button>
      )}
    </li>
  )
}
