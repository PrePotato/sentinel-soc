import axios from 'axios'

// Backend base URL. In dev / Docker it's empty → requests go to `/api`
// (Vite proxy / nginx, same origin). In a decoupled prod deploy set
// VITE_API_URL to the backend origin (e.g. https://sentinel-soc-api.onrender.com).
export const API_BASE = (import.meta.env.VITE_API_URL ?? '').replace(/\/+$/, '')

// Axios instance pointed at the FastAPI backend.
// A stored JWT is attached automatically; 401s bubble up to the auth store.
export const api = axios.create({ baseURL: `${API_BASE}/api`, timeout: 12_000 })

const TOKEN_KEY = 'soc.jwt'

export const tokenStore = {
  get: () => localStorage.getItem(TOKEN_KEY),
  set: (t: string) => localStorage.setItem(TOKEN_KEY, t),
  clear: () => localStorage.removeItem(TOKEN_KEY),
}

api.interceptors.request.use((cfg) => {
  const t = tokenStore.get()
  if (t) cfg.headers.Authorization = `Bearer ${t}`
  return cfg
})

// Report whether the backend is reachable so the UI can show live vs. sim mode.
export async function pingBackend(): Promise<boolean> {
  try {
    await api.get('/health', { timeout: 1500 })
    return true
  } catch {
    return false
  }
}
