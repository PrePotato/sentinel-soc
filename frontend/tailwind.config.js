/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: '#070B14',
          bg2: '#0A1120',
          panel: '#0E1626',
          panel2: '#121C30',
          border: '#1E2A44',
          borderlit: '#274063',
          text: '#E2E8F0',
          muted: '#94A3B8',
          dim: '#5B6B85',
          cyan: '#22D3EE',
          blue: '#3B82F6',
          violet: '#8B5CF6',
        },
        sev: {
          critical: '#F43F5E',
          high: '#FB923C',
          medium: '#FACC15',
          low: '#38BDF8',
          ok: '#34D399',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
      },
      boxShadow: {
        'glow-cyan': '0 0 24px -4px rgba(34,211,238,0.45)',
        'glow-blue': '0 0 24px -4px rgba(59,130,246,0.45)',
        'glow-crit': '0 0 24px -4px rgba(244,63,94,0.55)',
        panel: '0 1px 0 0 rgba(148,163,184,0.06) inset, 0 8px 30px -12px rgba(0,0,0,0.6)',
      },
      keyframes: {
        'pulse-glow': {
          '0%,100%': { opacity: '1', boxShadow: '0 0 0 0 rgba(34,211,238,0.4)' },
          '50%': { opacity: '0.85', boxShadow: '0 0 18px 2px rgba(34,211,238,0.15)' },
        },
        'fade-up': {
          '0%': { opacity: '0', transform: 'translateY(6px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        ping2: {
          '75%,100%': { transform: 'scale(2.2)', opacity: '0' },
        },
        blink: { '0%,100%': { opacity: '1' }, '50%': { opacity: '0.25' } },
      },
      animation: {
        'pulse-glow': 'pulse-glow 2.4s ease-in-out infinite',
        'fade-up': 'fade-up 0.35s ease-out both',
        ping2: 'ping2 1.6s cubic-bezier(0,0,0.2,1) infinite',
        blink: 'blink 1.1s step-end infinite',
      },
    },
  },
  plugins: [],
}
