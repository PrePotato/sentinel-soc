import type { Severity } from '../../lib/types'
import { SEV, classNames } from '../../lib/format'

export function SeverityBadge({ sev, className }: { sev: Severity; className?: string }) {
  const s = SEV[sev]
  return (
    <span className={classNames('chip', s.bg, s.border, s.text, className)}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: s.hex }} />
      {s.label}
    </span>
  )
}
