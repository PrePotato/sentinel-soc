import { useEffect, useRef, useState, type ReactNode } from 'react'
import { classNames } from '../../lib/format'

// Smoothly counts from the previous value to the next on every change.
function useCountUp(value: number, ms = 500) {
  const [display, setDisplay] = useState(value)
  const fromRef = useRef(value)
  const raf = useRef(0)
  useEffect(() => {
    const from = fromRef.current
    const start = performance.now()
    cancelAnimationFrame(raf.current)
    const tick = (now: number) => {
      const p = Math.min(1, (now - start) / ms)
      const eased = 1 - Math.pow(1 - p, 3)
      setDisplay(Math.round(from + (value - from) * eased))
      if (p < 1) raf.current = requestAnimationFrame(tick)
      else fromRef.current = value
    }
    raf.current = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf.current)
  }, [value, ms])
  return display
}

interface StatCardProps {
  label: string
  value: number
  icon: ReactNode
  accent?: string // hex for glow + icon
  suffix?: string
  trend?: number[] // sparkline series
  danger?: boolean
}

export function StatCard({ label, value, icon, accent = '#22D3EE', suffix, trend, danger }: StatCardProps) {
  const shown = useCountUp(value)
  return (
    <div
      className={classNames(
        'panel panel-hover group relative overflow-hidden px-4 py-3',
        danger && 'border-sev-critical/40',
      )}
    >
      {/* corner glow */}
      <div
        className="pointer-events-none absolute -right-8 -top-10 h-24 w-24 rounded-full opacity-30 blur-2xl transition-opacity group-hover:opacity-60"
        style={{ background: danger ? '#F43F5E' : accent }}
      />
      <div className="flex items-start justify-between">
        <div>
          <div className="text-[10.5px] font-semibold uppercase tracking-[0.14em] text-soc-muted">{label}</div>
          <div className="mt-1 flex items-baseline gap-1">
            <span
              className="tnum text-2xl font-bold leading-none text-soc-text"
              style={{ textShadow: `0 0 16px ${danger ? '#F43F5E55' : accent + '55'}` }}
            >
              {shown.toLocaleString()}
            </span>
            {suffix && <span className="text-xs font-medium text-soc-muted">{suffix}</span>}
          </div>
        </div>
        <div
          className="grid h-9 w-9 place-items-center rounded-lg border"
          style={{ borderColor: (danger ? '#F43F5E' : accent) + '55', color: danger ? '#F43F5E' : accent, background: (danger ? '#F43F5E' : accent) + '14' }}
        >
          {icon}
        </div>
      </div>
      {trend && trend.length > 1 && <Spark data={trend} color={danger ? '#F43F5E' : accent} />}
    </div>
  )
}

function Spark({ data, color }: { data: number[]; color: string }) {
  const w = 120
  const h = 22
  const max = Math.max(...data, 1)
  const min = Math.min(...data, 0)
  const span = max - min || 1
  const pts = data.map((v, i) => {
    const x = (i / (data.length - 1)) * w
    const y = h - ((v - min) / span) * h
    return `${x.toFixed(1)},${y.toFixed(1)}`
  })
  return (
    <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" className="mt-2 h-6 w-full opacity-80">
      <polyline points={pts.join(' ')} fill="none" stroke={color} strokeWidth={1.5} vectorEffect="non-scaling-stroke" />
    </svg>
  )
}
