import { useMemo } from 'react'
import { MapContainer, TileLayer, CircleMarker, Polyline, Tooltip } from 'react-leaflet'
import 'leaflet/dist/leaflet.css'
import { Globe } from 'lucide-react'
import { Panel } from '../ui/Panel'
import { useSocStore } from '../../store/useSocStore'
import { SEV } from '../../lib/format'
import type { GeoAttack } from '../../lib/types'

// The monitored asset the attacks are converging on.
const HQ: [number, number] = [37.77, -122.42]

export function GeoAttackMap() {
  const geo = useSocStore((s) => s.geo)

  const byCountry = useMemo(() => {
    const total = geo.reduce((a, g) => a + g.count, 0) || 1
    return [...geo].sort((a, b) => b.count - a.count).map((g) => ({ ...g, pct: Math.round((g.count / total) * 100) }))
  }, [geo])

  return (
    <Panel
      title="Geo-IP Attack Origins"
      icon={<Globe size={14} />}
      live
      bodyClass="p-0"
      actions={<span className="text-[10px] text-soc-dim">{geo.length} sources</span>}
    >
      <div className="grid grid-cols-1 lg:grid-cols-[1fr_180px]">
        <div className="relative h-[300px] overflow-hidden rounded-bl-xl border-r border-soc-border/60">
          <MapContainer center={[25, 5]} zoom={1.4} minZoom={1} scrollWheelZoom={false} style={{ height: '100%', width: '100%' }} worldCopyJump attributionControl={false}>
            <TileLayer url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png" />
            {geo.map((g) => (
              <Polyline
                key={`l_${g.id}`}
                positions={[[g.lat, g.lng], HQ]}
                pathOptions={{ className: 'attack-line', color: SEV[g.severity].hex, weight: 1, opacity: 0.55 }}
              />
            ))}
            {geo.map((g) => <AttackPin key={g.id} g={g} />)}
            <CircleMarker center={HQ} radius={6} pathOptions={{ className: 'hq-pulse', color: '#22D3EE', fillColor: '#22D3EE', fillOpacity: 0.9, weight: 2 }}>
              <Tooltip>HQ · Monitored asset</Tooltip>
            </CircleMarker>
          </MapContainer>
        </div>

        {/* Country stats */}
        <div className="max-h-[300px] overflow-y-auto p-2.5">
          <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-soc-dim">Top origins</div>
          <div className="space-y-1.5">
            {byCountry.map((g) => (
              <div key={g.id} className="text-xs">
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-1.5 text-soc-muted">
                    <span className="h-2 w-2 rounded-full" style={{ background: SEV[g.severity].hex }} />
                    {g.country}
                  </span>
                  <span className="tnum font-mono text-soc-dim">{g.count}</span>
                </div>
                <div className="mt-0.5 h-1 overflow-hidden rounded-full bg-soc-panel">
                  <div className="h-full rounded-full" style={{ width: `${g.pct}%`, background: SEV[g.severity].hex }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </Panel>
  )
}

function AttackPin({ g }: { g: GeoAttack }) {
  const c = SEV[g.severity].hex
  return (
    <CircleMarker
      center={[g.lat, g.lng]}
      radius={Math.min(11, 3 + g.count / 6)}
      pathOptions={{ color: c, fillColor: c, fillOpacity: 0.35, weight: 1.5 }}
    >
      <Tooltip>
        <div className="font-mono text-[11px]">
          <div className="font-bold">{g.country}</div>
          <div>{g.ip}</div>
          <div>{g.count} attempts · {g.severity}</div>
        </div>
      </Tooltip>
    </CircleMarker>
  )
}
