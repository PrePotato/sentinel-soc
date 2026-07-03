// Tiny WebAudio blip generator for critical alerts — no assets needed.
let ctx: AudioContext | null = null

function ac(): AudioContext | null {
  if (typeof window === 'undefined') return null
  if (!ctx) {
    const C = window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext
    if (!C) return null
    ctx = new C()
  }
  return ctx
}

export function beep(kind: 'critical' | 'high' | 'info' = 'info') {
  const a = ac()
  if (!a) return
  if (a.state === 'suspended') a.resume().catch(() => {})
  const now = a.currentTime
  const freqs = kind === 'critical' ? [880, 1320] : kind === 'high' ? [660] : [520]
  freqs.forEach((f, i) => {
    const osc = a.createOscillator()
    const gain = a.createGain()
    osc.type = 'sine'
    osc.frequency.value = f
    const start = now + i * 0.16
    gain.gain.setValueAtTime(0.0001, start)
    gain.gain.exponentialRampToValueAtTime(0.14, start + 0.02)
    gain.gain.exponentialRampToValueAtTime(0.0001, start + 0.22)
    osc.connect(gain).connect(a.destination)
    osc.start(start)
    osc.stop(start + 0.24)
  })
}
