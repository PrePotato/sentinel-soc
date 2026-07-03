import { useMemo } from 'react'
import CytoscapeComponent from 'react-cytoscapejs'
import cytoscape from 'cytoscape'
import type { Core, ElementDefinition, Stylesheet } from 'cytoscape'
import { Network, Router, Server, Smartphone, Cpu, HelpCircle, Monitor, X } from 'lucide-react'
import { Panel } from '../ui/Panel'
import { useSocStore } from '../../store/useSocStore'
import { SEV, classNames, timeAgo } from '../../lib/format'
import type { Device, DeviceType } from '../../lib/types'

const TYPE_COLOR: Record<DeviceType, string> = {
  router: '#22D3EE',
  server: '#3B82F6',
  pc: '#8B5CF6',
  phone: '#34D399',
  iot: '#FACC15',
  unknown: '#F43F5E',
}

const TYPE_ICON: Record<DeviceType, typeof Server> = {
  router: Router, server: Server, pc: Monitor, phone: Smartphone, iot: Cpu, unknown: HelpCircle,
}

const stylesheet: Stylesheet[] = [
  {
    selector: 'node[color]',
    style: {
      'background-color': 'data(color)',
      'border-width': 2,
      'border-color': 'data(border)',
      width: 'data(size)',
      height: 'data(size)',
      label: 'data(label)',
      color: '#94A3B8',
      'font-size': 8,
      'font-family': 'JetBrains Mono, monospace',
      'text-margin-y': 6,
      'text-valign': 'bottom',
      'text-halign': 'center',
      'overlay-opacity': 0,
    },
  },
  { selector: 'node[susp = "1"]', style: { 'border-color': '#F43F5E', 'border-width': 3 } },
  {
    selector: 'edge',
    style: {
      width: 1.2,
      'line-color': 'rgba(56,189,248,0.25)',
      'curve-style': 'bezier',
      'target-arrow-shape': 'none',
    },
  },
  { selector: 'node:selected', style: { 'border-color': '#22D3EE', 'border-width': 4 } },
]

export function NetworkMap() {
  const devices = useSocStore((s) => s.devices)
  const selectedId = useSocStore((s) => s.selectedDeviceId)
  const select = useSocStore((s) => s.select)
  const selected = devices.find((d) => d.id === selectedId) ?? null

  const elements = useMemo<ElementDefinition[]>(() => {
    const nodes: ElementDefinition[] = devices.map((d) => ({
      data: {
        id: d.id,
        label: d.hostname,
        color: TYPE_COLOR[d.type],
        border: d.suspicious ? '#F43F5E' : TYPE_COLOR[d.type],
        size: d.type === 'router' ? 34 : 20,
        susp: d.suspicious ? '1' : '0',
      },
    }))
    const edges: ElementDefinition[] = devices
      .filter((d) => d.parentId)
      .map((d) => ({ data: { id: `e_${d.id}`, source: d.parentId!, target: d.id } }))
    return [...nodes, ...edges]
  }, [devices])

  const layout = { name: 'concentric', concentric: (n: { data: (k: string) => string }) => (n.data('size') > 30 ? 2 : 1), levelWidth: () => 1, minNodeSpacing: 34, animate: true } as unknown as cytoscape.LayoutOptions

  return (
    <Panel
      title="Live Network Map"
      icon={<Network size={14} />}
      live
      bodyClass="relative p-0"
      actions={<span className="text-[10px] text-soc-dim">{devices.length} nodes</span>}
    >
      <div className="relative h-[340px] w-full overflow-hidden rounded-b-xl">
        {elements.length > 0 && (
          <CytoscapeComponent
            elements={elements}
            stylesheet={stylesheet}
            layout={layout}
            style={{ width: '100%', height: '100%' }}
            cy={(cy: Core) => {
              cy.removeAllListeners()
              cy.on('tap', 'node', (e) => select(e.target.id()))
              cy.on('tap', (e) => { if (e.target === cy) select(null) })
            }}
            minZoom={0.5}
            maxZoom={2.5}
          />
        )}

        {/* Legend */}
        <div className="pointer-events-none absolute left-3 top-3 flex flex-wrap gap-x-3 gap-y-1 text-[10px] text-soc-muted">
          {(Object.keys(TYPE_COLOR) as DeviceType[]).map((t) => (
            <span key={t} className="flex items-center gap-1">
              <span className="h-2 w-2 rounded-full" style={{ background: TYPE_COLOR[t] }} />
              {t}
            </span>
          ))}
        </div>

        {selected && <DeviceDetail device={selected} onClose={() => select(null)} />}
      </div>
    </Panel>
  )
}

function DeviceDetail({ device, onClose }: { device: Device; onClose: () => void }) {
  const Icon = TYPE_ICON[device.type]
  return (
    <div className="absolute bottom-3 right-3 w-64 animate-fade-up rounded-lg border border-soc-borderlit bg-soc-bg2/95 p-3 shadow-glow-cyan backdrop-blur">
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-2">
          <div className="grid h-8 w-8 place-items-center rounded-md border" style={{ borderColor: TYPE_COLOR[device.type] + '66', color: TYPE_COLOR[device.type], background: TYPE_COLOR[device.type] + '18' }}>
            <Icon size={16} />
          </div>
          <div>
            <div className="font-mono text-sm font-semibold text-soc-text">{device.hostname}</div>
            <div className="text-[10px] tracking-wide text-soc-dim">{device.fingerprint}</div>
          </div>
        </div>
        <button onClick={onClose} className="text-soc-dim hover:text-soc-text" aria-label="Close"><X size={14} /></button>
      </div>
      <dl className="mt-2.5 space-y-1 font-mono text-[11px]">
        <Row k="IP" v={device.ip} />
        <Row k="MAC" v={device.mac} />
        <Row k="Vendor" v={device.vendor} />
        <Row k="OS" v={device.os} />
        <Row k="VLAN" v={String(device.vlan)} />
        <Row k="Ports" v={device.openPorts.length ? device.openPorts.join(', ') : '—'} />
        <Row k="Traffic" v={`${device.trafficMbps} Mbps`} />
        <Row k="Seen" v={timeAgo(device.lastSeen)} />
      </dl>
      <div className={classNames('mt-2 rounded border px-2 py-1 text-center text-[11px] font-semibold', device.suspicious ? SEV.critical.bg + ' ' + SEV.critical.border + ' ' + SEV.critical.text : SEV.ok.bg + ' ' + SEV.ok.border + ' ' + SEV.ok.text)}>
        {device.suspicious ? '⚠ Flagged suspicious' : '✓ Trusted device'}
      </div>
    </div>
  )
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex justify-between gap-2">
      <dt className="text-soc-dim">{k}</dt>
      <dd className="truncate text-soc-muted">{v}</dd>
    </div>
  )
}
