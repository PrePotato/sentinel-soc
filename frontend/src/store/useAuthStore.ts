import { create } from 'zustand'
import { api, tokenStore } from '../lib/api'
import type { User } from '../lib/types'

interface AuthState {
  user: User | null
  booting: boolean
  error: string | null
  login: (username: string, password: string) => Promise<boolean>
  logout: () => void
  restore: () => Promise<void>
}

// Decode a JWT payload without a dependency (display only — never trusted).
function decode(token: string): User | null {
  try {
    const p = JSON.parse(atob(token.split('.')[1]))
    if (!p?.sub) return null
    return { username: p.sub, role: p.role === 'admin' ? 'admin' : 'viewer' }
  } catch {
    return null
  }
}

// Demo accounts used when the backend is offline so the app is always explorable.
const DEMO: Record<string, { password: string; role: 'admin' | 'viewer' }> = {
  admin: { password: 'admin', role: 'admin' },
  viewer: { password: 'viewer', role: 'viewer' },
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  booting: true,
  error: null,

  async login(username, password) {
    set({ error: null })
    // Try the real backend first.
    try {
      const body = new URLSearchParams({ username, password })
      const { data } = await api.post('/auth/login', body, { timeout: 4000 })
      tokenStore.set(data.access_token)
      set({ user: decode(data.access_token) ?? { username, role: data.role ?? 'viewer' } })
      return true
    } catch {
      // Offline demo fallback.
      const acct = DEMO[username.toLowerCase()]
      if (acct && acct.password === password) {
        set({ user: { username: username.toLowerCase(), role: acct.role } })
        return true
      }
      set({ error: 'Invalid credentials. Try admin / admin or viewer / viewer.' })
      return false
    }
  },

  logout() {
    tokenStore.clear()
    set({ user: null })
  },

  async restore() {
    const t = tokenStore.get()
    if (t) {
      const u = decode(t)
      if (u) {
        set({ user: u, booting: false })
        return
      }
      tokenStore.clear()
    }
    set({ booting: false })
  },
}))
