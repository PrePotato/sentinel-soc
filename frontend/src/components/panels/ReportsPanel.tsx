import { useState } from 'react'
import { jsPDF } from 'jspdf'
import autoTable from 'jspdf-autotable'
import { FileText, Download, ShieldAlert, Bug, ScanLine, Bell } from 'lucide-react'
import { Panel } from '../ui/Panel'
import { useSocStore } from '../../store/useSocStore'
import { clockTime } from '../../lib/format'

type ReportKind = 'threat' | 'ports' | 'vulns' | 'alerts'

const REPORTS: { kind: ReportKind; label: string; icon: React.ReactNode; desc: string }[] = [
  { kind: 'threat', label: 'Threat Summary', icon: <ShieldAlert size={15} />, desc: 'Posture, score & suspicious devices' },
  { kind: 'ports', label: 'Port Scan', icon: <ScanLine size={15} />, desc: 'All discovered ports & risk levels' },
  { kind: 'vulns', label: 'Vulnerabilities', icon: <Bug size={15} />, desc: 'CVE findings & remediation' },
  { kind: 'alerts', label: 'Alert Log', icon: <Bell size={15} />, desc: 'Full alert history & actions' },
]

export function ReportsPanel() {
  const [last, setLast] = useState<string | null>(null)

  function generate(kind: ReportKind) {
    const s = useSocStore.getState()
    const doc = new jsPDF({ unit: 'pt', format: 'a4' })
    const now = new Date()

    // Header band
    doc.setFillColor(10, 17, 32)
    doc.rect(0, 0, doc.internal.pageSize.getWidth(), 70, 'F')
    doc.setTextColor(34, 211, 238)
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(18)
    doc.text('SENTINEL SOC', 40, 34)
    doc.setTextColor(148, 163, 184)
    doc.setFont('helvetica', 'normal')
    doc.setFontSize(10)
    doc.text(`${REPORTS.find((r) => r.kind === kind)!.label} Report`, 40, 52)
    doc.text(`Generated ${now.toLocaleString()}`, doc.internal.pageSize.getWidth() - 40, 52, { align: 'right' })

    const theme = { headStyles: { fillColor: [30, 42, 68] as [number, number, number] }, styles: { fontSize: 8 }, startY: 90 }

    if (kind === 'threat') {
      doc.setTextColor(30, 41, 59)
      doc.setFontSize(11)
      doc.text(`Threat score: ${s.stats?.threatScore ?? 0}/100   ·   System health: ${s.stats?.healthScore ?? 0}/100`, 40, 90)
      autoTable(doc, {
        ...theme, startY: 104,
        head: [['Metric', 'Value']],
        body: [
          ['Threats today', String(s.stats?.threatsToday ?? 0)],
          ['Open ports', String(s.stats?.openPorts ?? 0)],
          ['Suspicious IPs', String(s.stats?.suspiciousIps ?? 0)],
          ['Failed logins', String(s.stats?.failedLogins ?? 0)],
          ['Active devices', String(s.stats?.activeDevices ?? 0)],
        ],
      })
      autoTable(doc, {
        ...theme, startY: (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 16,
        head: [['Suspicious device', 'IP', 'Type', 'Vendor']],
        body: s.devices.filter((d) => d.suspicious).map((d) => [d.hostname, d.ip, d.type, d.vendor]),
      })
    } else if (kind === 'ports') {
      autoTable(doc, { ...theme, head: [['Port', 'Service', 'Proto', 'Status', 'Risk', 'Host']], body: s.ports.map((p) => [String(p.port), p.service, p.protocol, p.status, p.risk, p.host]) })
    } else if (kind === 'vulns') {
      autoTable(doc, { ...theme, head: [['CVE', 'Severity', 'CVSS', 'Service', 'Title', 'Remediation']], body: s.vulns.map((v) => [v.id, v.severity, v.cvss.toFixed(1), v.service, v.title, v.remediation]) })
    } else {
      autoTable(doc, { ...theme, head: [['Time', 'Severity', 'Type', 'Message', 'Action']], body: s.alerts.map((a) => [clockTime(a.ts), a.severity, a.type, a.message, a.action]) })
    }

    doc.save(`sentinel-${kind}-${now.toISOString().slice(0, 10)}.pdf`)
    setLast(`${REPORTS.find((r) => r.kind === kind)!.label} exported at ${clockTime(Date.now())}`)
  }

  return (
    <Panel title="Report Generation" icon={<FileText size={14} />}>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        {REPORTS.map((r) => (
          <button key={r.kind} onClick={() => generate(r.kind)}
            className="group flex items-center gap-3 rounded-lg border border-soc-border bg-soc-panel2/40 p-3 text-left transition hover:border-soc-cyan/40 hover:shadow-glow-cyan">
            <div className="grid h-9 w-9 shrink-0 place-items-center rounded-md border border-soc-cyan/40 bg-soc-cyan/10 text-soc-cyan">{r.icon}</div>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-1 text-sm font-semibold text-soc-text">{r.label}</div>
              <div className="truncate text-[11px] text-soc-dim">{r.desc}</div>
            </div>
            <Download size={15} className="text-soc-dim transition group-hover:text-soc-cyan" />
          </button>
        ))}
      </div>
      {last && <div className="mt-3 rounded-md border border-sev-ok/30 bg-sev-ok/10 px-3 py-1.5 text-[11px] text-sev-ok">✓ {last}</div>}
    </Panel>
  )
}
