import { useEffect, useRef } from 'react'
import { useSocStore } from '../store/useSocStore'
import { beep } from '../lib/sound'
import {
  makeSnapshot,
  generateAlert,
  nextTimelinePoint,
  TrafficSim,
} from '../lib/mockData'
import type { Alert, Snapshot, Stats } from '../lib/types'

// One shared engine for the whole app. Prefers a real backend WebSocket and
// silently degrades to the local mock stream so the dashboard is never empty.
export function useLiveFeed() {
  const started = useRef(false)

  useEffect(() => {
    if (started.current) return // guard React 18 StrictMode double-invoke
    started.current = true

    const store = useSocStore.getState
    let timers: ReturnType<typeof setInterval>[] = []
    let socket: WebSocket | null = null
    let disposed = false

    const onAlert = (a: Alert) => {
      store().pushAlert(a)
      if (a.severity === 'critical' && store().soundOn) beep('critical')
      else if (a.severity === 'high' && store().soundOn) beep('high')
    }

    // ── Mock stream ────────────────────────────────────────────
    const startSim = () => {
      if (disposed) return
      store().setConn({ connected: false, simMode: true })
      const sim = new TrafficSim(store().devices)
      timers.push(
        setInterval(() => {
          sim.setDevices(store().devices)
          store().pushPacket(sim.next())
        }, 750),
      )
      timers.push(
        setInterval(() => {
          const a = generateAlert(store().devices)
          if (a) onAlert(a)
        }, 4200),
      )
      timers.push(setInterval(() => store().pushTimeline(nextTimelinePoint()), 5000))
      timers.push(
        setInterval(() => {
          const s = store().stats
          if (!s) return
          const jitter = (v: number, d: number, min = 0) => Math.max(min, v + Math.round((Math.random() - 0.45) * d))
          const next: Stats = {
            ...s,
            threatsToday: jitter(s.threatsToday, 3),
            failedLogins: jitter(s.failedLogins, 6),
            suspiciousIps: Math.max(0, jitter(s.suspiciousIps, 2)),
            healthScore: Math.min(100, Math.max(15, jitter(s.healthScore, 2, 15))),
            threatScore: Math.min(100, Math.max(5, jitter(s.threatScore, 3, 5))),
          }
          store().setStats(next)
        }, 3000),
      )
    }

    const stopTimers = () => {
      timers.forEach(clearInterval)
      timers = []
    }

    // ── Backend WebSocket ──────────────────────────────────────
    const connect = () => {
      try {
        const proto = location.protocol === 'https:' ? 'wss' : 'ws'
        socket = new WebSocket(`${proto}://${location.host}/ws/live`)
      } catch {
        startSim()
        return
      }

      const failSafe = setTimeout(() => {
        if (socket && socket.readyState !== WebSocket.OPEN) {
          socket.close()
          startSim()
        }
      }, 2500)

      socket.onopen = () => {
        clearTimeout(failSafe)
        stopTimers()
        store().setConn({ connected: true, simMode: false })
      }
      socket.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data) as { type: string; payload: unknown }
          const s = store()
          switch (msg.type) {
            case 'snapshot': s.hydrate(msg.payload as Snapshot); break
            case 'stats': s.setStats(msg.payload as Stats); break
            case 'packet': s.pushPacket(msg.payload as never); break
            case 'timeline': s.pushTimeline(msg.payload as never); break
            case 'alert': onAlert(msg.payload as Alert); break
          }
        } catch { /* ignore malformed frames */ }
      }
      socket.onclose = () => {
        clearTimeout(failSafe)
        if (!disposed) startSim() // degrade to sim if backend drops
      }
      socket.onerror = () => socket?.close()
    }

    // Seed immediately so the first paint is populated, then connect.
    const seed: Snapshot = makeSnapshot()
    store().hydrate(seed)
    const seedSim = new TrafficSim(seed.devices)
    for (let i = 0; i < 25; i++) store().pushPacket(seedSim.next())
    connect()

    return () => {
      disposed = true
      stopTimers()
      socket?.close()
      started.current = false
    }
  }, [])
}

// Manual re-scan: regenerate the environment (used by the "Scan" button).
export function useManualScan() {
  return () => {
    const s = useSocStore.getState()
    s.setScanning(true)
    setTimeout(() => {
      s.hydrate(makeSnapshot())
      s.setScanning(false)
    }, 1400)
  }
}
