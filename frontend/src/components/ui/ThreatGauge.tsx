import { SEV } from '../../lib/format'
import type { Severity } from '../../lib/types'

function bandFor(score: number): Severity {
  if (score >= 80) return 'critical'
  if (score >= 60) return 'high'
  if (score >= 35) return 'medium'
  if (score >= 15) return 'low'
  return 'ok'
}

// Radial threat-severity gauge (0–100) with a neon arc.
export function ThreatGauge({ score, size = 132 }: { score: number; size?: number }) {
  const band = bandFor(score)
  const color = SEV[band].hex
  const r = size / 2 - 10
  const c = Math.PI * r // half-circle circumference
  const dash = (score / 100) * c
  const cx = size / 2
  const cy = size / 2 + 6

  return (
    <div className="flex flex-col items-center">
      <svg width={size} height={size / 1.55} viewBox={`0 0 ${size} ${size / 1.55}`}>
        <defs>
          <linearGradient id="gauge" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0" stopColor="#34D399" />
            <stop offset="0.4" stopColor="#FACC15" />
            <stop offset="0.7" stopColor="#FB923C" />
            <stop offset="1" stopColor="#F43F5E" />
          </linearGradient>
        </defs>
        {/* track */}
        <path
          d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
          fill="none"
          stroke="#1E2A44"
          strokeWidth={10}
          strokeLinecap="round"
        />
        {/* value arc */}
        <path
          d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
          fill="none"
          stroke="url(#gauge)"
          strokeWidth={10}
          strokeLinecap="round"
          strokeDasharray={`${dash} ${c}`}
          style={{ transition: 'stroke-dasharray 0.7s cubic-bezier(0.4,0,0.2,1)', filter: `drop-shadow(0 0 6px ${color}88)` }}
        />
      </svg>
      <div className="-mt-9 flex flex-col items-center">
        <span className="tnum text-3xl font-bold" style={{ color, textShadow: `0 0 18px ${color}66` }}>
          {Math.round(score)}
        </span>
        <span className="text-[10px] font-semibold uppercase tracking-[0.16em]" style={{ color }}>
          {SEV[band].label} risk
        </span>
      </div>
    </div>
  )
}
