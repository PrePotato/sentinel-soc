// ─────────────────────────────────────────────────────────────
// Shared domain types for the SOC dashboard.
// Kept intentionally close to the backend Pydantic schemas so the
// live WebSocket payloads and the mock feed are interchangeable.
// ─────────────────────────────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'ok'
export type DeviceType = 'router' | 'server' | 'pc' | 'phone' | 'iot' | 'unknown'
export type PortStatus = 'open' | 'filtered' | 'closed'
export type Protocol = 'TCP' | 'UDP' | 'ICMP'

export interface Stats {
  threatsToday: number
  openPorts: number
  suspiciousIps: number
  failedLogins: number
  activeDevices: number
  healthScore: number // 0-100
  threatScore: number // 0-100 (severity index)
}

export interface Device {
  id: string
  ip: string
  mac: string
  hostname: string
  type: DeviceType
  vendor: string // OUI-derived MAC vendor (e.g. "Hikvision", "Shenzhen Bilian")
  os: string
  fingerprint: string // human device fingerprint (e.g. "IP Camera · Embedded Linux")
  vlan: number
  suspicious: boolean
  lastSeen: number
  trafficMbps: number
  openPorts: number[] // ports this device exposes — drives ports table + traffic sim
  parentId?: string // link toward the gateway for the network graph
}

export interface Port {
  id: string
  port: number
  service: string
  status: PortStatus
  protocol: Protocol
  risk: Severity
  host: string
}

export interface PacketEvent {
  id: string
  ts: number
  srcIp: string
  dstIp: string
  srcPort: number
  dstPort: number
  protocol: Protocol
  kind: string // TCP flags / message type: SYN, SYN-ACK, PSH, DNS-Q, TLS-Hello…
  service: string // resolved app-layer service (HTTPS, DNS, SSH, RTSP…)
  bytes: number
  info: string // one-line human summary, capture-style
  risk: Severity
  flagged: boolean
}

export interface Vulnerability {
  id: string // CVE-xxxx-xxxxx
  severity: Severity
  cvss: number
  service: string
  title: string
  description: string
  remediation: string
  published: string
}

export interface Alert {
  id: string
  ts: number
  type: string
  severity: Severity
  message: string
  action: string
  technique?: string // MITRE ATT&CK id + name, e.g. "T1046 · Network Service Scanning"
  source?: string
  srcMac?: string
  ack?: boolean
}

export interface GeoAttack {
  id: string
  ts: number
  country: string
  countryCode: string
  lat: number
  lng: number
  ip: string
  count: number
  severity: Severity
}

export interface TimelinePoint {
  t: number
  logins: number
  scans: number
  suspicious: number
  blocked: number
}

export interface Snapshot {
  stats: Stats
  devices: Device[]
  ports: Port[]
  vulns: Vulnerability[]
  geo: GeoAttack[]
  timeline: TimelinePoint[]
}

export interface User {
  username: string
  role: 'admin' | 'viewer'
}
