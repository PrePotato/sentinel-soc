import { useState } from 'react'
import { Sidebar } from '../components/layout/Sidebar'
import { Topbar } from '../components/layout/Topbar'
import { SummaryBar } from '../components/layout/SummaryBar'
import { OverviewPanel } from '../components/panels/OverviewPanel'
import { NetworkMap } from '../components/panels/NetworkMap'
import { PortScanner } from '../components/panels/PortScanner'
import { ThreatTimeline } from '../components/panels/ThreatTimeline'
import { PacketFeed } from '../components/panels/PacketFeed'
import { VulnScanner } from '../components/panels/VulnScanner'
import { GeoAttackMap } from '../components/panels/GeoAttackMap'
import { AlertsPanel } from '../components/panels/AlertsPanel'
import { AiAssistant } from '../components/panels/AiAssistant'
import { ReportsPanel } from '../components/panels/ReportsPanel'
import { useLiveFeed } from '../hooks/useLiveFeed'

// Anchor wrapper so sidebar deep-links land below the sticky topbar.
function Section({ id, span, children }: { id: string; span: string; children: React.ReactNode }) {
  return <div id={id} className={`scroll-mt-24 ${span}`}>{children}</div>
}

export function Dashboard() {
  useLiveFeed() // one engine drives every panel
  const [menuOpen, setMenuOpen] = useState(false)
  const [query, setQuery] = useState('')

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar open={menuOpen} onClose={() => setMenuOpen(false)} />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar onMenu={() => setMenuOpen(true)} query={query} setQuery={setQuery} />
        <main className="flex-1 space-y-3 overflow-y-auto p-3 sm:p-4">
          <div id="overview" className="scroll-mt-24">
            <SummaryBar />
          </div>

          <div className="grid grid-cols-1 gap-3 xl:grid-cols-12">
            <Section id="overview-posture" span="xl:col-span-4"><OverviewPanel /></Section>
            <Section id="network" span="xl:col-span-8"><NetworkMap /></Section>

            <Section id="timeline" span="xl:col-span-8"><ThreatTimeline /></Section>
            <Section id="alerts" span="xl:col-span-4"><AlertsPanel /></Section>

            <Section id="ports" span="xl:col-span-6"><PortScanner query={query} /></Section>
            <Section id="packets" span="xl:col-span-6"><PacketFeed query={query} /></Section>

            <Section id="vulns" span="xl:col-span-5"><VulnScanner query={query} /></Section>
            <Section id="geo" span="xl:col-span-7"><GeoAttackMap /></Section>

            <Section id="ai" span="xl:col-span-7"><AiAssistant /></Section>
            <Section id="reports" span="xl:col-span-5"><ReportsPanel /></Section>
          </div>

          <footer className="py-4 text-center text-[11px] text-soc-dim">
            SENTINEL SOC · demo build · telemetry is simulated unless a FastAPI backend is connected
          </footer>
        </main>
      </div>
    </div>
  )
}
