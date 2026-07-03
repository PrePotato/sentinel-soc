import type { ReactNode } from 'react'
import { classNames } from '../../lib/format'

interface PanelProps {
  title?: string
  icon?: ReactNode
  actions?: ReactNode
  live?: boolean
  className?: string
  bodyClass?: string
  children: ReactNode
}

// The canonical surface for every dashboard module: frosted card, neon title
// rail, optional "live" pulse, and a scrollable body.
export function Panel({ title, icon, actions, live, className, bodyClass, children }: PanelProps) {
  return (
    <section className={classNames('panel flex min-h-0 flex-col', className)}>
      {title && (
        <header className="flex items-center justify-between gap-2 border-b border-soc-border/70 px-4 py-2.5">
          <div className="panel-title">
            {icon && <span className="text-soc-cyan">{icon}</span>}
            <span>{title}</span>
            {live && (
              <span className="relative ml-1 inline-flex h-1.5 w-1.5">
                <span className="absolute inline-flex h-full w-full animate-ping2 rounded-full bg-sev-ok/70" />
                <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-sev-ok" />
              </span>
            )}
          </div>
          {actions && <div className="flex items-center gap-1.5">{actions}</div>}
        </header>
      )}
      <div className={classNames('min-h-0 flex-1', bodyClass ?? 'p-4')}>{children}</div>
    </section>
  )
}
