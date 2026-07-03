import { useMemo } from 'react'
import { Line } from 'react-chartjs-2'
import {
  Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement,
  Filler, Tooltip, Legend, type ChartOptions,
} from 'chart.js'
import { Activity } from 'lucide-react'
import { Panel } from '../ui/Panel'
import { useSocStore } from '../../store/useSocStore'
import { clockTime } from '../../lib/format'

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Filler, Tooltip, Legend)

const SERIES: { key: 'logins' | 'scans' | 'suspicious' | 'blocked'; label: string; color: string }[] = [
  { key: 'suspicious', label: 'Suspicious', color: '#F43F5E' },
  { key: 'logins', label: 'Login attempts', color: '#8B5CF6' },
  { key: 'scans', label: 'Port scans', color: '#FACC15' },
  { key: 'blocked', label: 'Blocked', color: '#34D399' },
]

export function ThreatTimeline() {
  const timeline = useSocStore((s) => s.timeline)

  const data = useMemo(() => {
    const labels = timeline.map((t) => clockTime(t.t))
    return {
      labels,
      datasets: SERIES.map((s) => ({
        label: s.label,
        data: timeline.map((t) => t[s.key]),
        borderColor: s.color,
        backgroundColor: s.color + '22',
        fill: s.key === 'suspicious',
        tension: 0.35,
        borderWidth: 1.8,
        pointRadius: 0,
        pointHoverRadius: 4,
        pointHoverBackgroundColor: s.color,
      })),
    }
  }, [timeline])

  const options: ChartOptions<'line'> = {
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 250 },
    interaction: { mode: 'index', intersect: false },
    plugins: {
      legend: {
        position: 'top',
        align: 'end',
        labels: { color: '#94A3B8', boxWidth: 8, boxHeight: 8, usePointStyle: true, font: { size: 10 } },
      },
      tooltip: {
        backgroundColor: '#0A1120',
        borderColor: '#1E2A44',
        borderWidth: 1,
        titleColor: '#E2E8F0',
        bodyColor: '#94A3B8',
        padding: 10,
        cornerRadius: 8,
      },
    },
    scales: {
      x: {
        grid: { color: 'rgba(148,163,184,0.06)' },
        ticks: { color: '#5B6B85', font: { size: 9, family: 'JetBrains Mono' }, maxTicksLimit: 8, maxRotation: 0 },
      },
      y: {
        grid: { color: 'rgba(148,163,184,0.06)' },
        ticks: { color: '#5B6B85', font: { size: 9, family: 'JetBrains Mono' }, precision: 0 },
        beginAtZero: true,
      },
    },
  }

  return (
    <Panel title="Threat Timeline" icon={<Activity size={14} />} live actions={<span className="text-[10px] text-soc-dim">last {timeline.length} min</span>}>
      <div className="h-[240px]">
        {timeline.length > 1 ? <Line data={data} options={options} /> : <Empty />}
      </div>
    </Panel>
  )
}

function Empty() {
  return <div className="grid h-full place-items-center text-sm text-soc-dim">Collecting telemetry…</div>
}
