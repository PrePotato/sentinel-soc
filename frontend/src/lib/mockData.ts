// ─────────────────────────────────────────────────────────────
// Realistic SOC telemetry. Device fingerprints use real OUI (MAC
// vendor) prefixes; alerts are believable attack scenarios tagged
// with MITRE ATT&CK techniques; traffic is a stateful flow
// simulation (real TCP/DNS/TLS sequences + attack patterns); CVEs
// are real, recognizable advisories. The backend mirrors all of
// this and additionally pulls a live NVD feed.
// ─────────────────────────────────────────────────────────────
import type {
  Alert, Device, DeviceType, GeoAttack, PacketEvent, Port, Protocol,
  Severity, Snapshot, Stats, TimelinePoint, Vulnerability,
} from './types'

let seq = 0
export const uid = (p = 'id') => `${p}_${Date.now().toString(36)}_${(seq++).toString(36)}`

const pick = <T>(a: T[]): T => a[Math.floor(Math.random() * a.length)]
const rnd = (min: number, max: number) => Math.floor(Math.random() * (max - min + 1)) + min
const chance = (p: number) => Math.random() < p

// ── Real OUI (MAC vendor) prefixes ───────────────────────────
const OUI: Record<string, string[]> = {
  Cisco: ['00:1A:2F', '00:25:45', 'F4:CF:E2'],
  Apple: ['3C:15:C2', 'A4:83:E7', 'F0:18:98', '8C:85:90'],
  Samsung: ['34:23:BA', '5C:0A:5B', 'C0:BD:D1'],
  'TP-Link': ['50:C7:BF', 'A4:2B:B0', 'EC:08:6B'],
  Netgear: ['20:E5:2A', 'A0:40:A0', '00:14:6C'],
  Dell: ['00:14:22', 'B8:CA:3A', 'F8:BC:12'],
  HP: ['00:1B:78', '3C:D9:2B', '70:5A:0F'],
  Ubiquiti: ['24:A4:3C', 'FC:EC:DA', 'B4:FB:E4'],
  'Raspberry Pi': ['B8:27:EB', 'DC:A6:32', 'E4:5F:01'],
  Intel: ['3C:97:0E', '94:65:9C', 'A0:88:B4'],
  Hikvision: ['4C:BD:8F', '28:57:BE', 'C0:56:E3'],
  Espressif: ['24:0A:C4', '3C:71:BF', '84:0D:8E'],
  'Amazon Technologies': ['FC:65:DE', '44:65:0D', '68:37:E9'],
  Google: ['F4:F5:D8', '6C:AD:F8', '1C:F2:9A'],
  'Shenzhen Bilian': ['0C:8C:24', 'A0:56:B2', 'C8:3A:35'],
}
const macFor = (vendor: string) =>
  `${pick(OUI[vendor] ?? OUI['Shenzhen Bilian'])}:${rnd(0, 255).toString(16).padStart(2, '0')}:${rnd(0, 255).toString(16).padStart(2, '0')}:${rnd(0, 255).toString(16).padStart(2, '0')}`.toUpperCase()

// ── Device profiles (vendor + OS + hostname + services cohere) ─
interface Profile {
  vendors: string[]
  os: string[]
  fp: string
  host: () => string
  services: number[]
}
const hex = (n: number) => Array.from({ length: n }, () => rnd(0, 15).toString(16)).join('')
const NAMES = ['jarrod', 'sofia', 'ravi', 'mei', 'liam', 'noor', 'dane', 'ivy']
const PROFILES: Record<DeviceType, Profile> = {
  router: { vendors: ['Cisco', 'Ubiquiti', 'Netgear', 'TP-Link'], os: ['RouterOS 7.14', 'Cisco IOS XE 17.9', 'EdgeOS 2.0'], fp: 'Gateway / Firewall', host: () => pick(['edge-fw-01', 'core-gw', 'rtr-hq-01']), services: [22, 443, 53, 161] },
  server: { vendors: ['Dell', 'HP', 'Intel'], os: ['Ubuntu 22.04 LTS', 'Windows Server 2022', 'RHEL 9.3', 'Debian 12'], fp: 'Server', host: () => pick(['web-prod', 'db-primary', 'k8s-node', 'jenkins-ci', 'nas-vault', 'mail-relay']) + '-' + rnd(1, 6), services: [22, 80, 443, 3306, 5432, 6379, 8080] },
  pc: { vendors: ['Dell', 'HP', 'Apple', 'Intel'], os: ['Windows 11 23H2', 'macOS 14.4 Sonoma', 'Windows 10 22H2'], fp: 'Workstation', host: () => pick([`DESKTOP-${hex(7).toUpperCase()}`, `FIN-WS-0${rnd(1, 9)}`, `LAPTOP-HR0${rnd(1, 9)}`, `MacBook-Pro-${pick(NAMES)}`]), services: [445, 139, 3389, 135] },
  phone: { vendors: ['Apple', 'Samsung', 'Google'], os: ['iOS 17.4', 'Android 14', 'iPadOS 17.4'], fp: 'Mobile Device', host: () => pick([`iPhone-${pick(NAMES)}`, `Galaxy-S24-${pick(NAMES)}`, `Pixel-8-${pick(NAMES)}`]), services: [] },
  iot: { vendors: ['Hikvision', 'Espressif', 'Amazon Technologies', 'Google', 'Raspberry Pi'], os: ['Embedded Linux', 'FreeRTOS', 'Tasmota 13.2'], fp: 'IoT Device', host: () => pick(['cam-lobby-01', 'cam-loadingbay', 'nest-thermostat', 'echo-kitchen', 'hvac-ctrl-2', 'rpi-sensor-3', 'printer-mfp-2']), services: [80, 554, 8080, 1883, 23] },
  unknown: { vendors: ['Shenzhen Bilian'], os: ['—', 'Unknown'], fp: 'Unidentified', host: () => (chance(0.5) ? '' : `android-${hex(12)}`), services: [] },
}
const FP_BY_HOST: Record<string, string> = { 'cam-lobby-01': 'IP Camera', 'cam-loadingbay': 'IP Camera', 'nest-thermostat': 'Smart Thermostat', 'echo-kitchen': 'Smart Speaker', 'hvac-ctrl-2': 'HVAC Controller', 'rpi-sensor-3': 'Sensor Node', 'printer-mfp-2': 'Network Printer' }

const SERVICE_NAME: Record<number, string> = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 135: 'MSRPC', 139: 'NetBIOS',
  161: 'SNMP', 443: 'HTTPS', 445: 'SMB', 554: 'RTSP', 1883: 'MQTT', 3306: 'MySQL',
  3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP-alt', 27017: 'MongoDB',
}
const SERVICE_RISK: Record<number, Severity> = {
  23: 'critical', 3389: 'critical', 445: 'critical', 22: 'high', 21: 'high', 3306: 'high',
  5432: 'high', 6379: 'high', 27017: 'high', 1883: 'medium', 554: 'medium', 80: 'medium',
  8080: 'medium', 25: 'medium', 161: 'medium', 135: 'medium', 139: 'medium', 53: 'low', 443: 'low',
}

// ── Real, recognizable CVEs (offline set; backend adds live NVD) ─
const CVES: Omit<Vulnerability, 'published'>[] = [
  { id: 'CVE-2021-44228', severity: 'critical', cvss: 10.0, service: 'Apache Log4j 2.14.1', title: 'Log4Shell — JNDI RCE', description: 'JNDI features used in log messages do not protect against attacker-controlled LDAP lookups, enabling remote code execution.', remediation: 'Upgrade to Log4j 2.17.1+; set log4j2.formatMsgNoLookups=true; block outbound LDAP.' },
  { id: 'CVE-2024-3094', severity: 'critical', cvss: 10.0, service: 'xz / liblzma 5.6.0', title: 'XZ Utils backdoor', description: 'Malicious code in the upstream tarball modifies liblzma to compromise sshd authentication on affected distros.', remediation: 'Downgrade xz to 5.4.x; audit sshd; rotate keys on exposed hosts.' },
  { id: 'CVE-2019-0708', severity: 'critical', cvss: 9.8, service: 'Microsoft RDP', title: 'BlueKeep — pre-auth RCE', description: 'A use-after-free in Remote Desktop Services allows unauthenticated remote code execution over RDP.', remediation: 'Patch MS advisory; enable NLA; restrict 3389 to VPN.' },
  { id: 'CVE-2022-22965', severity: 'critical', cvss: 9.8, service: 'Spring Framework', title: 'Spring4Shell — RCE', description: 'Data binding on JDK 9+ allows remote code execution via crafted class-loader access.', remediation: 'Upgrade Spring to 5.3.18+/5.2.20+; apply WAF rule for classLoader payloads.' },
  { id: 'CVE-2017-0144', severity: 'high', cvss: 8.1, service: 'Windows SMBv1', title: 'EternalBlue — SMB RCE', description: 'SMBv1 mishandles crafted packets, permitting remote code execution (WannaCry/NotPetya vector).', remediation: 'Apply MS17-010; disable SMBv1; block 445 at perimeter.' },
  { id: 'CVE-2014-0160', severity: 'high', cvss: 7.5, service: 'OpenSSL 1.0.1', title: 'Heartbleed — memory disclosure', description: 'A missing bounds check in the TLS heartbeat extension leaks up to 64KB of process memory, including keys.', remediation: 'Upgrade OpenSSL ≥1.0.1g; reissue certificates; rotate secrets.' },
  { id: 'CVE-2023-44487', severity: 'high', cvss: 7.5, service: 'HTTP/2 stack', title: 'HTTP/2 Rapid Reset DDoS', description: 'Rapid stream creation/cancellation enables a high-efficiency denial-of-service against HTTP/2 servers.', remediation: 'Patch server; rate-limit stream resets; enable connection flood protection.' },
  { id: 'CVE-2023-25690', severity: 'medium', cvss: 6.1, service: 'nginx 1.18', title: 'HTTP request smuggling', description: 'Inconsistent Transfer-Encoding parsing between proxy and origin enables cache poisoning and request smuggling.', remediation: 'Update nginx; normalize upstream headers; reject ambiguous TE/CL.' },
  { id: 'CVE-2011-3389', severity: 'low', cvss: 3.7, service: 'TLS 1.0/1.1', title: 'Deprecated TLS protocol enabled', description: 'Legacy TLS 1.0/1.1 remains offered by the endpoint, exposing clients to downgrade and known cipher weaknesses.', remediation: 'Disable TLS < 1.2; enforce modern cipher suites.' },
]

// ── Geo attack origins ───────────────────────────────────────
const COUNTRIES: [string, string, number, number][] = [
  ['Russia', 'RU', 55.75, 37.61], ['China', 'CN', 39.9, 116.4], ['United States', 'US', 38.9, -77.03],
  ['Brazil', 'BR', -15.79, -47.88], ['India', 'IN', 28.61, 77.2], ['Iran', 'IR', 35.69, 51.38],
  ['North Korea', 'KP', 39.03, 125.75], ['Nigeria', 'NG', 9.07, 7.49], ['Germany', 'DE', 52.52, 13.4],
  ['Vietnam', 'VN', 21.02, 105.83], ['Netherlands', 'NL', 52.37, 4.9], ['Ukraine', 'UA', 50.45, 30.52],
]

const localIp = (sub = 1) => `192.168.${sub}.${rnd(2, 254)}`
const extIp = () => `${pick([45, 185, 193, 5, 91, 103, 194, 212])}.${rnd(0, 255)}.${rnd(0, 255)}.${rnd(1, 254)}`

// ── Devices ──────────────────────────────────────────────────
function makeDevice(type: DeviceType, i: number): Device {
  const p = PROFILES[type]
  const vendor = pick(p.vendors)
  const host = p.host()
  const suspicious = type === 'unknown' ? chance(0.8) : chance(0.1)
  const svcCount = type === 'phone' ? 0 : type === 'unknown' ? (suspicious ? rnd(0, 1) : 0) : rnd(1, Math.min(4, p.services.length))
  const openPorts = [...p.services].sort(() => Math.random() - 0.5).slice(0, svcCount)
  return {
    id: uid('dev'), ip: localIp(1), mac: macFor(vendor),
    hostname: host || `unknown-${i}`, type, vendor,
    os: pick(p.os), fingerprint: `${FP_BY_HOST[host] ?? p.fp} · ${vendor}`,
    vlan: type === 'iot' || type === 'unknown' ? 30 : type === 'server' ? 10 : 20,
    suspicious, lastSeen: Date.now() - rnd(0, 90_000),
    trafficMbps: rnd(0, 60), openPorts, parentId: 'dev_gateway',
  }
}

function makeDevices(): Device[] {
  const gw: Device = {
    id: 'dev_gateway', ip: '192.168.1.1', mac: macFor('Cisco'), hostname: 'edge-fw-01',
    type: 'router', vendor: 'Cisco', os: 'Cisco IOS XE 17.9', fingerprint: 'Gateway / Firewall · Cisco',
    vlan: 1, suspicious: false, lastSeen: Date.now(), trafficMbps: rnd(60, 140), openPorts: [22, 443, 53, 161],
  }
  const layout: DeviceType[] = ['server', 'server', 'pc', 'pc', 'phone', 'iot', 'iot', 'pc', 'unknown', 'phone', 'server', 'iot']
  const devices = [gw]
  const n = rnd(9, 12)
  for (let i = 0; i < n; i++) devices.push(makeDevice(layout[i % layout.length], i))
  return devices
}

function makePorts(devices: Device[]): Port[] {
  const ports: Port[] = []
  for (const d of devices) {
    for (const port of d.openPorts) {
      ports.push({
        id: uid('port'), port, service: SERVICE_NAME[port] ?? 'unknown',
        protocol: port === 53 || port === 161 || port === 1883 ? 'UDP' : 'TCP',
        risk: d.suspicious && SERVICE_RISK[port] === 'low' ? 'medium' : (SERVICE_RISK[port] ?? 'medium'),
        status: chance(0.82) ? 'open' : chance(0.5) ? 'filtered' : 'closed', host: d.ip,
      })
    }
  }
  return ports.sort((a, b) => a.port - b.port)
}

function makeVulns(): Vulnerability[] {
  return CVES.map((c) => ({ ...c, published: new Date(Date.now() - rnd(30, 900) * 86_400_000).toISOString().slice(0, 10) }))
}

function makeGeo(): GeoAttack[] {
  return COUNTRIES.slice(0, rnd(6, 10)).map((c) => ({
    id: uid('geo'), ts: Date.now() - rnd(0, 120_000), country: c[0], countryCode: c[1],
    lat: c[2], lng: c[3], ip: extIp(), count: rnd(1, 40),
    severity: pick<Severity>(['critical', 'high', 'high', 'medium', 'low']),
  }))
}

function makeTimeline(): TimelinePoint[] {
  const now = Date.now()
  return Array.from({ length: 30 }, (_, i) => ({
    t: now - (30 - i) * 60_000,
    logins: rnd(0, 14) + (chance(0.15) ? rnd(10, 30) : 0), scans: rnd(0, 8),
    suspicious: rnd(0, 6) + (chance(0.1) ? rnd(6, 18) : 0), blocked: rnd(0, 10),
  }))
}

function scoreFrom(devices: Device[], ports: Port[], vulns: Vulnerability[]): number {
  const susp = devices.filter((d) => d.suspicious).length
  const critPorts = ports.filter((p) => p.risk === 'critical' && p.status === 'open').length
  const critVulns = vulns.filter((v) => v.severity === 'critical').length
  return Math.min(100, Math.max(6, susp * 6 + critPorts * 9 + critVulns * 12 + rnd(2, 10)))
}

export function makeSnapshot(): Snapshot {
  const devices = makeDevices()
  const ports = makePorts(devices)
  const vulns = makeVulns()
  const geo = makeGeo()
  const timeline = makeTimeline()
  const threatScore = scoreFrom(devices, ports, vulns)
  const stats: Stats = {
    threatsToday: rnd(18, 140), openPorts: ports.filter((p) => p.status === 'open').length,
    suspiciousIps: devices.filter((d) => d.suspicious).length + rnd(1, 6), failedLogins: rnd(40, 320),
    activeDevices: devices.length, healthScore: Math.max(20, 100 - Math.round(threatScore * 0.7)), threatScore,
  }
  return { stats, devices, ports, vulns, geo, timeline }
}

// ── Believable attack scenarios (MITRE ATT&CK) ───────────────
function portList(d: Device): string {
  const ps = d.openPorts.length ? d.openPorts : [22, 3389, 445]
  return ps.slice(0, 3).join(', ')
}

export function generateAlert(devices: Device[]): Alert | null {
  if (!chance(0.55)) return null
  const internal = devices.filter((d) => d.id !== 'dev_gateway')
  const target = pick(internal.filter((d) => d.type === 'server')) ?? pick(internal)
  const rogue = pick(internal.filter((d) => d.suspicious)) ?? pick(internal.filter((d) => d.type === 'unknown')) ?? pick(internal)
  const attacker = extIp()

  type S = { type: string; sev: Severity; msg: string; act: string; tech: string; src: string; mac?: string }
  const scenarios: S[] = [
    { type: 'Port Scan', sev: 'high', src: rogue.ip, mac: rogue.mac,
      msg: `Unrecognized device ${rogue.ip} (MAC vendor: ${rogue.vendor}) initiated repeated SYN scans on ports ${portList(target)} — ${rnd(120, 400)} probes in ${rnd(12, 40)}s`,
      act: 'Isolate on quarantine VLAN; block MAC at the switchport', tech: 'T1046 · Network Service Scanning' },
    { type: 'Brute Force', sev: 'critical', src: attacker,
      msg: `${rnd(180, 900)} failed RDP logins on ${target.hostname} (${target.ip}:3389) from ${attacker} in ${rnd(60, 180)}s`,
      act: 'Block source IP; enforce NLA + account lockout; move RDP behind VPN', tech: 'T1110 · Brute Force' },
    { type: 'Exploit Attempt', sev: 'critical', src: rogue.ip, mac: rogue.mac,
      msg: `SMBv1 exploit pattern (MS17-010 / EternalBlue) targeting ${target.ip}:445 from ${rogue.ip}`,
      act: 'Patch MS17-010; disable SMBv1; contain the source host', tech: 'T1210 · Exploitation of Remote Services' },
    { type: 'C2 Beacon', sev: 'high', src: pick(internal).ip,
      msg: `Periodic ${pick([512, 1024, 256])}-byte beacons to ${attacker}:443 every ${rnd(30, 90)}s — jittered pattern consistent with Cobalt Strike`,
      act: 'Block C2 destination; inspect process tree; hunt for the loader', tech: 'T1071 · Application Layer Protocol (C2)' },
    { type: 'Data Exfiltration', sev: 'high', src: target.ip,
      msg: `${(rnd(4, 24) / 10).toFixed(1)} GB outbound from ${target.hostname} (${target.ip}) to ${attacker} over ${rnd(4, 15)}m`,
      act: 'Throttle egress; trigger DLP review; snapshot the host for forensics', tech: 'T1048 · Exfiltration Over Alternative Protocol' },
    { type: 'DNS Tunneling', sev: 'medium', src: rogue.ip, mac: rogue.mac,
      msg: `High-entropy DNS queries from ${rogue.hostname} (${rogue.ip}) — ${rnd(1200, 6000)} TXT lookups to *.dnslog.cn`,
      act: 'Sinkhole the domain; enforce internal resolver + DNS logging', tech: 'T1071.004 · DNS' },
    { type: 'Unknown Device', sev: 'medium', src: rogue.ip, mac: rogue.mac,
      msg: `Unrecognized device joined VLAN ${rogue.vlan}: ${rogue.mac} (MAC vendor: ${rogue.vendor}), no DHCP hostname`,
      act: 'Verify MAC ownership; quarantine until approved via NAC', tech: 'T1200 · Hardware Additions' },
    { type: 'Lateral Movement', sev: 'high', src: pick(internal).ip,
      msg: `Anomalous admin-share access (PsExec) from ${pick(internal).hostname} to ${target.hostname} (${target.ip})`,
      act: 'Reset credentials; review privileged access; enable LSA protection', tech: 'T1021.002 · SMB/Windows Admin Shares' },
    { type: 'Exposed Service', sev: 'high', src: rogue.ip, mac: rogue.mac,
      msg: `Telnet (23) reachable on ${rogue.hostname} (${rogue.ip}) from WAN — legacy cleartext administration`,
      act: 'Disable Telnet; migrate to SSH; block 23 at the firewall', tech: 'T1190 · Exploit Public-Facing Application' },
  ]
  const s = pick(scenarios)
  return { id: uid('alert'), ts: Date.now(), type: s.type, severity: s.sev, message: s.msg, action: s.act, technique: s.tech, source: s.src, srcMac: s.mac, ack: false }
}

export function nextTimelinePoint(): TimelinePoint {
  return {
    t: Date.now(), logins: rnd(0, 14) + (chance(0.15) ? rnd(10, 34) : 0), scans: rnd(0, 8),
    suspicious: rnd(0, 6) + (chance(0.1) ? rnd(6, 20) : 0), blocked: rnd(0, 12),
  }
}

// ── Structured traffic simulation (stateful flows) ───────────
interface FlowStep { flags: string; bytes: number; dir: 'out' | 'in'; risk: Severity; flagged: boolean; info: string; dport?: number }
interface Flow { src: string; dst: string; sport: number; dport: number; service: string; proto: Protocol; steps: FlowStep[]; i: number }

const EPHEMERAL = () => rnd(49152, 65535)

export class TrafficSim {
  private flows: Flow[] = []
  constructor(private devices: Device[]) {}

  setDevices(devices: Device[]) { this.devices = devices }

  private hosts() { return this.devices.length ? this.devices : [{ ip: '192.168.1.10', openPorts: [443] } as Device] }

  private spawn(): Flow {
    const roll = Math.random()
    if (roll < 0.1) return this.portScan()
    if (roll < 0.16) return this.beacon()
    if (roll < 0.2) return this.exfil()
    if (roll < 0.32) return this.dns()
    if (roll < 0.42) return this.arp()
    return this.webFlow()
  }

  private webFlow(): Flow {
    const client = pick(this.hosts())
    const external = chance(0.6)
    const dstIp = external ? extIp() : pick(this.hosts()).ip
    const dport = external ? pick([443, 443, 80]) : pick(pick(this.hosts()).openPorts?.length ? pick(this.hosts()).openPorts : [443])
    const svc = SERVICE_NAME[dport] ?? 'HTTPS'
    const tls = dport === 443
    const steps: FlowStep[] = [
      { flags: 'SYN', bytes: 60, dir: 'out', risk: 'ok', flagged: false, info: 'connection open' },
      { flags: 'SYN-ACK', bytes: 60, dir: 'in', risk: 'ok', flagged: false, info: 'handshake' },
      { flags: 'ACK', bytes: 52, dir: 'out', risk: 'ok', flagged: false, info: 'established' },
      ...(tls
        ? [{ flags: 'TLS-ClientHello', bytes: rnd(230, 320), dir: 'out' as const, risk: 'low' as Severity, flagged: false, info: `TLSv1.3 → ${dstIp}` },
           { flags: 'TLS-ServerHello', bytes: rnd(1200, 1460), dir: 'in' as const, risk: 'ok' as Severity, flagged: false, info: 'cert exchange' }]
        : [{ flags: 'PSH', bytes: rnd(300, 620), dir: 'out' as const, risk: 'low' as Severity, flagged: false, info: `GET / ${svc}` },
           { flags: 'PSH', bytes: rnd(800, 1460), dir: 'in' as const, risk: 'ok' as Severity, flagged: false, info: '200 OK' }]),
      { flags: 'FIN-ACK', bytes: 52, dir: 'out', risk: 'ok', flagged: false, info: 'connection close' },
    ]
    return { src: client.ip, dst: dstIp, sport: EPHEMERAL(), dport, service: svc, proto: 'TCP', steps, i: 0 }
  }

  private dns(): Flow {
    const client = pick(this.hosts())
    const q = pick(['api.github.com', 'cdn.jsdelivr.net', 'login.microsoftonline.com', ' crl.pki.goog', 'ntp.ubuntu.com'])
    return {
      src: client.ip, dst: '192.168.1.1', sport: EPHEMERAL(), dport: 53, service: 'DNS', proto: 'UDP',
      steps: [
        { flags: 'DNS-Q', bytes: rnd(60, 90), dir: 'out', risk: 'ok', flagged: false, info: `A? ${q.trim()}` },
        { flags: 'DNS-R', bytes: rnd(90, 160), dir: 'in', risk: 'ok', flagged: false, info: `answer ${extIp()}` },
      ], i: 0,
    }
  }

  private arp(): Flow {
    const a = pick(this.hosts()); const b = pick(this.hosts())
    return {
      src: a.ip, dst: b.ip, sport: 0, dport: 0, service: 'ARP', proto: 'ICMP',
      steps: [
        { flags: 'ARP-who-has', bytes: 42, dir: 'out', risk: 'ok', flagged: false, info: `who has ${b.ip}?` },
        { flags: 'ARP-is-at', bytes: 42, dir: 'in', risk: 'ok', flagged: false, info: `${b.ip} is-at ${b.mac ?? '..'}` },
      ], i: 0,
    }
  }

  private portScan(): Flow {
    const attacker = chance(0.5) ? extIp() : (pick(this.devices.filter((d) => d.suspicious))?.ip ?? extIp())
    const target = pick(this.hosts())
    const scanPorts = [21, 22, 23, 80, 135, 139, 443, 445, 3306, 3389, 8080]
    const steps: FlowStep[] = scanPorts.map((port) => ({
      flags: 'SYN', bytes: 44, dir: 'out', risk: 'high', flagged: true, dport: port,
      info: `scan → ${target.ip}:${port} (${SERVICE_NAME[port] ?? '?'})`,
    }))
    return { src: attacker, dst: target.ip, sport: EPHEMERAL(), dport: scanPorts[0], service: 'SCAN', proto: 'TCP', steps, i: 0 }
  }

  private beacon(): Flow {
    const host = pick(this.hosts()); const c2 = extIp()
    return {
      src: host.ip, dst: c2, sport: EPHEMERAL(), dport: 443, service: 'HTTPS', proto: 'TCP',
      steps: Array.from({ length: 3 }, () => ({
        flags: 'PSH', bytes: pick([256, 512]), dir: 'out' as const, risk: 'high' as Severity, flagged: true,
        info: `C2 beacon → ${c2}:443`,
      })), i: 0,
    }
  }

  private exfil(): Flow {
    const host = pick(this.hosts().filter((d) => d.type === 'server')) ?? pick(this.hosts()); const dst = extIp()
    return {
      src: host.ip, dst, sport: EPHEMERAL(), dport: pick([443, 22, 21]), service: 'HTTPS', proto: 'TCP',
      steps: Array.from({ length: 4 }, () => ({
        flags: 'PSH', bytes: rnd(1200, 1460), dir: 'out' as const, risk: 'critical' as Severity, flagged: true,
        info: `bulk transfer → ${dst}`,
      })), i: 0,
    }
  }

  next(): PacketEvent {
    // Advance an existing flow (interleaves concurrent sessions) or open a new one.
    if (!this.flows.length || chance(0.4)) this.flows.push(this.spawn())
    const idx = rnd(0, this.flows.length - 1)
    const f = this.flows[idx]
    const step = f.steps[f.i]
    f.i += 1
    if (f.i >= f.steps.length) this.flows.splice(idx, 1)
    if (this.flows.length > 20) this.flows.shift()

    const outbound = step.dir === 'out'
    const dport = step.dport ?? f.dport
    return {
      id: uid('pkt'), ts: Date.now(),
      srcIp: outbound ? f.src : f.dst, dstIp: outbound ? f.dst : f.src,
      srcPort: outbound ? f.sport : dport, dstPort: outbound ? dport : f.sport,
      protocol: f.proto, kind: step.flags, service: f.service, bytes: step.bytes,
      info: step.info, risk: step.risk, flagged: step.flagged,
    }
  }
}
