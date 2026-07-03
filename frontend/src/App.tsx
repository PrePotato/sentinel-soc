import { useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Login } from './pages/Login'
import { Dashboard } from './pages/Dashboard'
import { useAuthStore } from './store/useAuthStore'

function Protected({ children }: { children: React.ReactNode }) {
  const user = useAuthStore((s) => s.user)
  const booting = useAuthStore((s) => s.booting)
  if (booting) return <BootScreen />
  return user ? <>{children}</> : <Navigate to="/login" replace />
}

function BootScreen() {
  return (
    <div className="grid h-screen place-items-center">
      <div className="flex items-center gap-2 text-sm text-soc-dim">
        <span className="h-2 w-2 animate-pulse rounded-full bg-soc-cyan" /> Initializing SOC engine…
      </div>
    </div>
  )
}

export default function App() {
  const restore = useAuthStore((s) => s.restore)
  useEffect(() => { restore() }, [restore])

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={<Protected><Dashboard /></Protected>} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
