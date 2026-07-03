import { useMemo } from 'react'
import { Terminal, Pause } from 'lucide-react'
import { Panel } from '../ui/Panel'
import { useSocStore } from '../../store/useSocStore'
import { SEV, classNames } from '../../lib/format'
import type { PacketEvent } from '../../lib/types'

export function PacketFeed({ query = '' }: { query?: string }) {
  const packets = useSocStore((s) => s.packets)
  const paused = useSocStore((s) => s.paused)

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase()
    const list = q ? packets.filter((p) => `${p.srcIp} ${p.dstIp} ${p.protocol} ${p.kind} ${p.service} ${p.info}`.toLowerCase().includes(q)) : packets
    return list.slice(0, 60)
  }, [packets, query])

  const flagged = packets.filter((p) => p.flagged).length

  return (
    <Panel
      title="Packet Inspection"
      icon={<Terminal size={14} />}
      live={!paused}
      bodyClass="p-0"
      actions={
        <div className="flex items-center gap-2">
          {paused && <span className="chip border-sev-medium/40 bg-sev-medium/10 text-sev-medium"><Pause size={10} /> paused</span>}
          <span className="text-[10px] text-soc-dim">{flagged} flagged</span>
        </div>
      }
    >
      <div className="scanlines relative h-[300px] overflow-hidden rounded-b-xl bg-[#060A12]">
        <div className="flex items-center gap-1.5 border-b border-soc-border/60 px-3 py-1.5 font-mono text-[10px] text-soc-dim">
          <span className="h-2 w-2 rounded-full bg-sev-critical/70" />
          <span className="h-2 w-2 rounded-full bg-sev-medium/70" />
          <span className="h-2 w-2 rounded-full bg-sev-ok/70" />
          <span className="ml-2">tcpdump -i any -nn · live capture</span>
          <span className="ml-auto animate-blink text-soc-cyan">▊</span>
        </div>
        <div className="h-[268px] overflow-auto px-3 py-1.5 font-mono text-[11px] leading-relaxed">
          {rows.map((p) => <PacketLine key={p.id} p={p} />)}
          {rows.length === 0 && <div className="py-8 text-center text-soc-dim">Awaiting packets…</div>}
        </div>
      </div>
    </Panel>
  )
}

function PacketLine({ p }: { p: PacketEvent }) {
  const c = SEV[p.risk].hex
  const t = new Date(p.ts).toLocaleTimeString('en-GB', { hour12: false })
  const src = p.srcPort ? `${p.srcIp}:${p.srcPort}` : p.srcIp
  const dst = p.dstPort ? `${p.dstIp}:${p.dstPort}` : p.dstIp
  return (
    <div className={classNames('flex items-center gap-2 whitespace-nowrap py-[1px]', p.flagged && 'rounded bg-sev-critical/[0.07] px-1')}>
      <span className="text-soc-dim">{t}</span>
      <span className="w-9 shrink-0" style={{ color: c }}>{p.protocol}</span>
      <span className="text-soc-muted">{src}</span>
      <span className="text-soc-dim">→</span>
      <span className="text-soc-muted">{dst}</span>
      <span className="rounded bg-soc-panel px-1 text-[10px]" style={{ color: c }}>{p.kind}</span>
      <span className="text-soc-dim">{p.bytes}b</span>
      {p.info && (
        <span className={classNames('truncate', p.flagged ? 'font-semibold text-sev-critical' : 'text-soc-dim')}>
          {p.flagged ? '⚠ ' : '· '}{p.info}
        </span>
      )}
    </div>
  )
}
