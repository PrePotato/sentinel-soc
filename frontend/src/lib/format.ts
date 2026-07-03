import type { Severity } from './types'

// Severity → tailwind-ready color values + labels. Single source of truth so
// badges, charts, map pins and the gauge all agree on the palette.
export const SEV: Record<
  Severity,
  { label: string; hex: string; text: string; bg: string; border: string; ring: string }
> = {
  critical: {
    label: 'Critical',
    hex: '#F43F5E',
    text: 'text-sev-critical',
    bg: 'bg-sev-critical/12',
    border: 'border-sev-critical/40',
    ring: 'shadow-glow-crit',
  },
  high: {
    label: 'High',
    hex: '#FB923C',
    text: 'text-sev-high',
    bg: 'bg-sev-high/12',
    border: 'border-sev-high/40',
    ring: '',
  },
  medium: {
    label: 'Medium',
    hex: '#FACC15',
    text: 'text-sev-medium',
    bg: 'bg-sev-medium/12',
    border: 'border-sev-medium/40',
    ring: '',
  },
  low: {
    label: 'Low',
    hex: '#38BDF8',
    text: 'text-sev-low',
    bg: 'bg-sev-low/12',
    border: 'border-sev-low/40',
    ring: '',
  },
  ok: {
    label: 'Info',
    hex: '#34D399',
    text: 'text-sev-ok',
    bg: 'bg-sev-ok/12',
    border: 'border-sev-ok/40',
    ring: '',
  },
}

export const SEV_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  ok: 4,
}

export function timeAgo(ts: number): string {
  const s = Math.max(0, Math.floor((Date.now() - ts) / 1000))
  if (s < 5) return 'now'
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

export function clockTime(ts: number): string {
  return new Date(ts).toLocaleTimeString('en-GB', { hour12: false })
}

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

export function classNames(...xs: (string | false | null | undefined)[]): string {
  return xs.filter(Boolean).join(' ')
}
