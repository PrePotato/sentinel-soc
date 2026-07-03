import { create } from 'zustand'
import type { Alert, Device, PacketEvent, Snapshot, Stats, TimelinePoint, Vulnerability, Port, GeoAttack } from '../lib/types'

const MAX_PACKETS = 120
const MAX_ALERTS = 60
const MAX_TIMELINE = 40

interface SocState {
  // connection
  connected: boolean // WebSocket to backend is live
  simMode: boolean // driving from the local mock engine
  paused: boolean
  soundOn: boolean

  // data
  stats: Stats | null
  devices: Device[]
  ports: Port[]
  vulns: Vulnerability[]
  geo: GeoAttack[]
  timeline: TimelinePoint[]
  packets: PacketEvent[]
  alerts: Alert[]
  selectedDeviceId: string | null
  scanning: boolean
  lastCriticalAt: number

  // actions
  hydrate: (s: Snapshot) => void
  setConn: (p: Partial<Pick<SocState, 'connected' | 'simMode'>>) => void
  setStats: (s: Stats) => void
  pushPacket: (p: PacketEvent) => void
  pushAlert: (a: Alert) => void
  pushTimeline: (t: TimelinePoint) => void
  ackAlert: (id: string) => void
  clearAlerts: () => void
  select: (id: string | null) => void
  togglePause: () => void
  toggleSound: () => void
  setScanning: (v: boolean) => void
}

export const useSocStore = create<SocState>((set) => ({
  connected: false,
  simMode: true,
  paused: false,
  soundOn: true,

  stats: null,
  devices: [],
  ports: [],
  vulns: [],
  geo: [],
  timeline: [],
  packets: [],
  alerts: [],
  selectedDeviceId: null,
  scanning: false,
  lastCriticalAt: 0,

  hydrate: (s) =>
    set({
      stats: s.stats,
      devices: s.devices,
      ports: s.ports,
      vulns: s.vulns,
      geo: s.geo,
      timeline: s.timeline,
    }),

  setConn: (p) => set(p),
  setStats: (stats) => set({ stats }),

  pushPacket: (p) =>
    set((st) => (st.paused ? st : { packets: [p, ...st.packets].slice(0, MAX_PACKETS) })),

  pushAlert: (a) =>
    set((st) => ({
      alerts: [a, ...st.alerts].slice(0, MAX_ALERTS),
      lastCriticalAt: a.severity === 'critical' ? Date.now() : st.lastCriticalAt,
    })),

  pushTimeline: (t) =>
    set((st) => ({ timeline: [...st.timeline, t].slice(-MAX_TIMELINE) })),

  ackAlert: (id) =>
    set((st) => ({ alerts: st.alerts.map((a) => (a.id === id ? { ...a, ack: true } : a)) })),

  clearAlerts: () => set({ alerts: [] }),
  select: (id) => set({ selectedDeviceId: id }),
  togglePause: () => set((st) => ({ paused: !st.paused })),
  toggleSound: () => set((st) => ({ soundOn: !st.soundOn })),
  setScanning: (v) => set({ scanning: v }),
}))
