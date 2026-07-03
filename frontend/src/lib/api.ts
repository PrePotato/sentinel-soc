import axios from 'axios'

// Axios instance pointed at the FastAPI backend (proxied by Vite in dev).
// A stored JWT is attached automatically; 401s bubble up to the auth store.
export const api = axios.create({ baseURL: '/api', timeout: 12_000 })

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
