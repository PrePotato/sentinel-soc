import { useRef, useState } from 'react'
import { Bot, CornerDownLeft, Loader2, Sparkles } from 'lucide-react'
import { Panel } from '../ui/Panel'
import { api } from '../../lib/api'
import { useSocStore } from '../../store/useSocStore'
import { SEV_ORDER } from '../../lib/format'

const QUICK = [
  'Explain the top threat right now',
  'Why is port 23 (Telnet) dangerous?',
  'Summarize open alerts and what to do',
  'What should I prioritize first?',
]

interface Turn { role: 'user' | 'ai'; text: string; live?: boolean }

export function AiAssistant() {
  const [turns, setTurns] = useState<Turn[]>([
    { role: 'ai', text: 'I analyze your live SOC telemetry. Ask me to explain a threat, a port, or your alert backlog — and I’ll suggest concrete mitigation steps.' },
  ])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const scroller = useRef<HTMLDivElement>(null)

  const scrollDown = () => requestAnimationFrame(() => scroller.current?.scrollTo({ top: 9e9, behavior: 'smooth' }))

  async function ask(question: string) {
    if (!question.trim() || busy) return
    setInput('')
    setTurns((t) => [...t, { role: 'user', text: question }])
    setBusy(true)
    scrollDown()

    const s = useSocStore.getState()
    const context = buildContext(s)
    try {
      const { data } = await api.post('/ai/explain', { question, context }, { timeout: 30000 })
      const text: string = data?.answer ?? localExplain(question, s)
      setTurns((t) => [...t, { role: 'ai', text, live: !!data?.live }])
    } catch {
      // Backend/AI unavailable → local heuristic analyst so the panel always answers.
      setTurns((t) => [...t, { role: 'ai', text: localExplain(question, s), live: false }])
    } finally {
      setBusy(false)
      scrollDown()
    }
  }

  return (
    <Panel
      title="AI Threat Analyst"
      icon={<Bot size={14} />}
      actions={<span className="chip border-soc-violet/40 bg-soc-violet/10 text-soc-violet"><Sparkles size={11} /> Claude</span>}
      bodyClass="flex flex-col p-0"
    >
      <div ref={scroller} className="max-h-[300px] min-h-[240px] flex-1 space-y-3 overflow-y-auto p-3">
        {turns.map((t, i) => <Bubble key={i} turn={t} />)}
        {busy && (
          <div className="flex items-center gap-2 text-xs text-soc-dim">
            <Loader2 size={13} className="animate-spin text-soc-violet" /> Analyzing telemetry…
          </div>
        )}
      </div>

      <div className="border-t border-soc-border/70 p-2.5">
        <div className="mb-2 flex flex-wrap gap-1.5">
          {QUICK.map((q) => (
            <button key={q} onClick={() => ask(q)} disabled={busy}
              className="rounded-md border border-soc-border bg-soc-panel/60 px-2 py-1 text-[11px] text-soc-muted transition hover:border-soc-violet/40 hover:text-soc-text disabled:opacity-50">
              {q}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && ask(input)}
            placeholder="Ask the analyst…"
            className="flex-1 rounded-md border border-soc-border bg-soc-bg/60 px-3 py-2 text-sm text-soc-text placeholder:text-soc-dim focus:border-soc-violet/60 focus:outline-none focus:ring-1 focus:ring-soc-violet/40"
          />
          <button onClick={() => ask(input)} disabled={busy || !input.trim()}
            className="grid h-9 w-9 place-items-center rounded-md border border-soc-violet/40 bg-soc-violet/15 text-soc-violet transition hover:bg-soc-violet/25 disabled:opacity-40">
            <CornerDownLeft size={16} />
          </button>
        </div>
      </div>
    </Panel>
  )
}

function Bubble({ turn }: { turn: Turn }) {
  const isUser = turn.role === 'user'
  return (
    <div className={isUser ? 'flex justify-end' : 'flex gap-2'}>
      {!isUser && (
        <div className="mt-0.5 grid h-6 w-6 shrink-0 place-items-center rounded-md bg-soc-violet/15 text-soc-violet">
          <Bot size={13} />
        </div>
      )}
      <div className={[
        'max-w-[85%] whitespace-pre-wrap rounded-lg px-3 py-2 text-xs leading-relaxed',
        isUser ? 'bg-soc-cyan/12 text-soc-text' : 'bg-soc-panel2/60 text-soc-muted',
      ].join(' ')}>
        {turn.text}
      </div>
    </div>
  )
}

// ── Context + offline heuristic analyst ──────────────────────
function buildContext(s: ReturnType<typeof useSocStore.getState>) {
  const critAlerts = s.alerts.filter((a) => !a.ack).slice(0, 6).map((a) => `${a.severity.toUpperCase()} ${a.type}: ${a.message}`)
  const critPorts = s.ports.filter((p) => p.status === 'open' && (p.risk === 'critical' || p.risk === 'high')).slice(0, 8).map((p) => `${p.port}/${p.service} (${p.risk}) on ${p.host}`)
  const worstVulns = [...s.vulns].sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]).slice(0, 4).map((v) => `${v.id} ${v.severity} CVSS${v.cvss} — ${v.title}`)
  const suspicious = s.devices.filter((d) => d.suspicious).map((d) => `${d.hostname} (${d.ip})`)
  return {
    threatScore: s.stats?.threatScore ?? null,
    healthScore: s.stats?.healthScore ?? null,
    openAlerts: critAlerts,
    riskyOpenPorts: critPorts,
    topVulnerabilities: worstVulns,
    suspiciousDevices: suspicious,
  }
}

function localExplain(q: string, s: ReturnType<typeof useSocStore.getState>): string {
  const ctx = buildContext(s)
  const ql = q.toLowerCase()

  if (ql.includes('telnet') || ql.includes('23') || ql.includes('port')) {
    return [
      'Telnet (TCP/23) transmits credentials and session data in cleartext, so anyone on the path can capture logins with a passive sniffer. It has no encryption, weak/no host authentication, and is a favourite target for IoT botnets (e.g. Mirai) that brute-force default creds.',
      '',
      'Mitigation:',
      '• Disable Telnet entirely; use SSH (TCP/22) with key-based auth instead.',
      '• If a legacy device must use it, isolate it on a management VLAN with no internet route.',
      '• Add an IDS signature for inbound 23 and alert on any external attempt.',
    ].join('\n')
  }

  if (ql.includes('prioriti') || ql.includes('first') || ql.includes('what should')) {
    const lines = ['Based on current telemetry, prioritise in this order:']
    if (ctx.riskyOpenPorts.length) lines.push(`1. Close/segment high-risk open ports — ${ctx.riskyOpenPorts.length} exposed (e.g. ${ctx.riskyOpenPorts[0]}).`)
    if (ctx.topVulnerabilities.length) lines.push(`2. Patch critical CVEs — ${ctx.topVulnerabilities[0]}.`)
    if (ctx.suspiciousDevices.length) lines.push(`3. Quarantine ${ctx.suspiciousDevices.length} suspicious device(s): ${ctx.suspiciousDevices.slice(0, 3).join(', ')}.`)
    if (ctx.openAlerts.length) lines.push(`4. Work the ${ctx.openAlerts.length} open alert(s), starting with the criticals.`)
    lines.push(`\nCurrent threat score is ${ctx.threatScore ?? '—'}/100 (system health ${ctx.healthScore ?? '—'}/100).`)
    return lines.join('\n')
  }

  if (ql.includes('alert')) {
    if (!ctx.openAlerts.length) return 'There are no open alerts right now — the environment is quiet. Keep the packet feed and geo map under observation for new activity.'
    return ['Open alerts requiring attention:', '', ...ctx.openAlerts.map((a, i) => `${i + 1}. ${a}`), '', 'Acknowledge each after triage; escalate any brute-force or exfiltration alerts to incident response immediately.'].join('\n')
  }

  // default: top threat
  const top = ctx.openAlerts[0] ?? ctx.riskyOpenPorts[0] ?? ctx.topVulnerabilities[0]
  return [
    `Highest-signal item: ${top ?? 'no active threats detected'}.`,
    '',
    `Threat score ${ctx.threatScore ?? '—'}/100. ${ctx.suspiciousDevices.length} suspicious device(s), ${ctx.riskyOpenPorts.length} risky open port(s), ${ctx.topVulnerabilities.length} notable CVE(s).`,
    '',
    'Recommended next step: contain the source (block IP / isolate device), confirm scope in the packet feed, then remediate the underlying exposure.',
    '',
    '(Offline analyst — start the backend with an ANTHROPIC_API_KEY for full Claude-powered analysis.)',
  ].join('\n')
}
