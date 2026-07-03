import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Lock, User, Loader2, ArrowRight } from 'lucide-react'
import { useAuthStore } from '../store/useAuthStore'

export function Login() {
  const nav = useNavigate()
  const login = useAuthStore((s) => s.login)
  const error = useAuthStore((s) => s.error)
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('admin')
  const [busy, setBusy] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    const ok = await login(username, password)
    setBusy(false)
    if (ok) nav('/')
  }

  return (
    <div className="grid min-h-screen place-items-center p-4">
      {/* animated backdrop rings */}
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute left-1/2 top-1/2 h-[520px] w-[520px] -translate-x-1/2 -translate-y-1/2 rounded-full border border-soc-cyan/10" />
        <div className="absolute left-1/2 top-1/2 h-[360px] w-[360px] -translate-x-1/2 -translate-y-1/2 rounded-full border border-soc-cyan/10" />
        <div className="absolute left-1/2 top-1/2 h-[200px] w-[200px] -translate-x-1/2 -translate-y-1/2 animate-pulse-glow rounded-full border border-soc-cyan/20" />
      </div>

      <div className="relative w-full max-w-sm animate-fade-up">
        <div className="mb-6 flex flex-col items-center text-center">
          <div className="grid h-14 w-14 place-items-center rounded-2xl border border-soc-cyan/40 bg-soc-cyan/10 shadow-glow-cyan">
            <Shield size={26} className="text-soc-cyan" />
          </div>
          <h1 className="mt-3 text-2xl font-bold tracking-tight text-soc-text">
            SENTINEL<span className="text-soc-cyan glow-text-cyan"> SOC</span>
          </h1>
          <p className="mt-1 text-xs uppercase tracking-[0.2em] text-soc-dim">Security Operations Center</p>
        </div>

        <form onSubmit={submit} className="panel space-y-3 p-5">
          <Field icon={<User size={15} />} label="Operator">
            <input value={username} onChange={(e) => setUsername(e.target.value)} autoFocus
              className="w-full bg-transparent text-sm text-soc-text placeholder:text-soc-dim focus:outline-none" placeholder="username" />
          </Field>
          <Field icon={<Lock size={15} />} label="Passphrase">
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-transparent text-sm text-soc-text placeholder:text-soc-dim focus:outline-none" placeholder="••••••" />
          </Field>

          {error && <div className="rounded-md border border-sev-critical/30 bg-sev-critical/10 px-3 py-2 text-xs text-sev-critical">{error}</div>}

          <button type="submit" disabled={busy}
            className="flex w-full items-center justify-center gap-2 rounded-lg border border-soc-cyan/50 bg-soc-cyan/15 py-2.5 text-sm font-semibold text-soc-cyan transition hover:bg-soc-cyan/25 disabled:opacity-60">
            {busy ? <Loader2 size={16} className="animate-spin" /> : <>Authenticate <ArrowRight size={15} /></>}
          </button>

          <div className="rounded-md border border-soc-border bg-soc-bg/40 px-3 py-2 text-[11px] text-soc-dim">
            Demo access — <span className="font-mono text-soc-muted">admin / admin</span> (full) or <span className="font-mono text-soc-muted">viewer / viewer</span> (read-only)
          </div>
        </form>
        <p className="mt-4 text-center text-[10px] text-soc-dim">JWT-secured · role-based access · session managed</p>
      </div>
    </div>
  )
}

function Field({ icon, label, children }: { icon: React.ReactNode; label: string; children: React.ReactNode }) {
  return (
    <label className="flex items-center gap-3 rounded-lg border border-soc-border bg-soc-bg/50 px-3 py-2.5 transition focus-within:border-soc-cyan/50 focus-within:ring-1 focus-within:ring-soc-cyan/30">
      <span className="text-soc-dim">{icon}</span>
      <div className="flex-1">
        <div className="text-[10px] uppercase tracking-wider text-soc-dim">{label}</div>
        {children}
      </div>
    </label>
  )
}
