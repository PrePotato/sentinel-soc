"""Telemetry engine.

Realistic SOC data: OUI-based device fingerprints, MITRE-tagged attack
scenarios, stateful flow-based traffic simulation, and real CVEs (augmented by
a live NVD feed — see nvd.py). Uses real Nmap scans when SOC_SCAN_ENABLED=1 and
the `nmap` binary is present; otherwise simulates.
"""
from __future__ import annotations

import random
import time
from datetime import datetime, timedelta

from .config import settings
from .schemas import (
    Alert, Device, GeoAttack, PacketEvent, Port, Snapshot, Stats,
    TimelinePoint, Vulnerability,
)

_seq = 0


def uid(prefix: str = "id") -> str:
    global _seq
    _seq += 1
    return f"{prefix}_{int(time.time()*1000):x}_{_seq:x}"


def now_ms() -> int:
    return int(time.time() * 1000)


def _chance(p: float) -> bool:
    return random.random() < p


def _rint(a: int, b: int) -> int:
    return random.randint(a, b)


# ── Real OUI (MAC vendor) prefixes ───────────────────────
OUI = {
    "Cisco": ["00:1A:2F", "00:25:45", "F4:CF:E2"],
    "Apple": ["3C:15:C2", "A4:83:E7", "F0:18:98", "8C:85:90"],
    "Samsung": ["34:23:BA", "5C:0A:5B", "C0:BD:D1"],
    "TP-Link": ["50:C7:BF", "A4:2B:B0", "EC:08:6B"],
    "Netgear": ["20:E5:2A", "A0:40:A0", "00:14:6C"],
    "Dell": ["00:14:22", "B8:CA:3A", "F8:BC:12"],
    "HP": ["00:1B:78", "3C:D9:2B", "70:5A:0F"],
    "Ubiquiti": ["24:A4:3C", "FC:EC:DA", "B4:FB:E4"],
    "Raspberry Pi": ["B8:27:EB", "DC:A6:32", "E4:5F:01"],
    "Intel": ["3C:97:0E", "94:65:9C", "A0:88:B4"],
    "Hikvision": ["4C:BD:8F", "28:57:BE", "C0:56:E3"],
    "Espressif": ["24:0A:C4", "3C:71:BF", "84:0D:8E"],
    "Amazon Technologies": ["FC:65:DE", "44:65:0D", "68:37:E9"],
    "Google": ["F4:F5:D8", "6C:AD:F8", "1C:F2:9A"],
    "Shenzhen Bilian": ["0C:8C:24", "A0:56:B2", "C8:3A:35"],
}


def _mac_for(vendor: str) -> str:
    prefix = random.choice(OUI.get(vendor, OUI["Shenzhen Bilian"]))
    tail = ":".join(f"{_rint(0,255):02x}" for _ in range(3))
    return f"{prefix}:{tail}".upper()


NAMES = ["jarrod", "sofia", "ravi", "mei", "liam", "noor", "dane", "ivy"]


def _hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


# type -> vendors, os, fingerprint label, hostname fn, typical services
PROFILES = {
    "router": (["Cisco", "Ubiquiti", "Netgear", "TP-Link"], ["RouterOS 7.14", "Cisco IOS XE 17.9", "EdgeOS 2.0"], "Gateway / Firewall",
               lambda: random.choice(["edge-fw-01", "core-gw", "rtr-hq-01"]), [22, 443, 53, 161]),
    "server": (["Dell", "HP", "Intel"], ["Ubuntu 22.04 LTS", "Windows Server 2022", "RHEL 9.3", "Debian 12"], "Server",
               lambda: random.choice(["web-prod", "db-primary", "k8s-node", "jenkins-ci", "nas-vault", "mail-relay"]) + f"-{_rint(1,6)}", [22, 80, 443, 3306, 5432, 6379, 8080]),
    "pc": (["Dell", "HP", "Apple", "Intel"], ["Windows 11 23H2", "macOS 14.4 Sonoma", "Windows 10 22H2"], "Workstation",
           lambda: random.choice([f"DESKTOP-{_hex(7).upper()}", f"FIN-WS-0{_rint(1,9)}", f"LAPTOP-HR0{_rint(1,9)}", f"MacBook-Pro-{random.choice(NAMES)}"]), [445, 139, 3389, 135]),
    "phone": (["Apple", "Samsung", "Google"], ["iOS 17.4", "Android 14", "iPadOS 17.4"], "Mobile Device",
              lambda: random.choice([f"iPhone-{random.choice(NAMES)}", f"Galaxy-S24-{random.choice(NAMES)}", f"Pixel-8-{random.choice(NAMES)}"]), []),
    "iot": (["Hikvision", "Espressif", "Amazon Technologies", "Google", "Raspberry Pi"], ["Embedded Linux", "FreeRTOS", "Tasmota 13.2"], "IoT Device",
            lambda: random.choice(["cam-lobby-01", "cam-loadingbay", "nest-thermostat", "echo-kitchen", "hvac-ctrl-2", "rpi-sensor-3", "printer-mfp-2"]), [80, 554, 8080, 1883, 23]),
    "unknown": (["Shenzhen Bilian"], ["—", "Unknown"], "Unidentified",
                lambda: ("" if _chance(0.5) else f"android-{_hex(12)}"), []),
}
FP_BY_HOST = {"cam-lobby-01": "IP Camera", "cam-loadingbay": "IP Camera", "nest-thermostat": "Smart Thermostat",
              "echo-kitchen": "Smart Speaker", "hvac-ctrl-2": "HVAC Controller", "rpi-sensor-3": "Sensor Node", "printer-mfp-2": "Network Printer"}

SERVICE_NAME = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 135: "MSRPC", 139: "NetBIOS",
                161: "SNMP", 443: "HTTPS", 445: "SMB", 554: "RTSP", 1883: "MQTT", 3306: "MySQL",
                3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-alt", 27017: "MongoDB"}
SERVICE_RISK = {23: "critical", 3389: "critical", 445: "critical", 22: "high", 21: "high", 3306: "high",
                5432: "high", 6379: "high", 27017: "high", 1883: "medium", 554: "medium", 80: "medium",
                8080: "medium", 25: "medium", 161: "medium", 135: "medium", 139: "medium", 53: "low", 443: "low"}

# Real, recognizable CVEs (offline set; nvd.py augments with live data)
CVES = [
    ("CVE-2021-44228", "critical", 10.0, "Apache Log4j 2.14.1", "Log4Shell — JNDI RCE (CVE-2021-44228)", "JNDI features used in log messages do not protect against attacker-controlled LDAP lookups, enabling remote code execution.", "Upgrade to Log4j 2.17.1+; set log4j2.formatMsgNoLookups=true; block outbound LDAP."),
    ("CVE-2024-3094", "critical", 10.0, "xz / liblzma 5.6.0", "XZ Utils backdoor (CVE-2024-3094)", "Malicious code in the upstream tarball modifies liblzma to compromise sshd authentication on affected distros.", "Downgrade xz to 5.4.x; audit sshd; rotate keys on exposed hosts."),
    ("CVE-2019-0708", "critical", 9.8, "Microsoft RDP", "BlueKeep — pre-auth RCE (CVE-2019-0708)", "A use-after-free in Remote Desktop Services allows unauthenticated remote code execution over RDP.", "Patch MS advisory; enable NLA; restrict 3389 to VPN."),
    ("CVE-2022-22965", "critical", 9.8, "Spring Framework", "Spring4Shell — RCE (CVE-2022-22965)", "Data binding on JDK 9+ allows remote code execution via crafted class-loader access.", "Upgrade Spring to 5.3.18+/5.2.20+; apply WAF rule for classLoader payloads."),
    ("CVE-2017-0144", "high", 8.1, "Windows SMBv1", "EternalBlue — SMB RCE (CVE-2017-0144)", "SMBv1 mishandles crafted packets, permitting remote code execution (WannaCry/NotPetya vector).", "Apply MS17-010; disable SMBv1; block 445 at perimeter."),
    ("CVE-2014-0160", "high", 7.5, "OpenSSL 1.0.1", "Heartbleed — memory disclosure (CVE-2014-0160)", "A missing bounds check in the TLS heartbeat extension leaks up to 64KB of process memory, including keys.", "Upgrade OpenSSL ≥1.0.1g; reissue certificates; rotate secrets."),
    ("CVE-2023-44487", "high", 7.5, "HTTP/2 stack", "HTTP/2 Rapid Reset DDoS (CVE-2023-44487)", "Rapid stream creation/cancellation enables a high-efficiency denial-of-service against HTTP/2 servers.", "Patch server; rate-limit stream resets; enable connection flood protection."),
    ("CVE-2023-25690", "medium", 6.1, "nginx 1.18", "HTTP request smuggling", "Inconsistent Transfer-Encoding parsing between proxy and origin enables cache poisoning and request smuggling.", "Update nginx; normalize upstream headers; reject ambiguous TE/CL."),
    ("CVE-2011-3389", "low", 3.7, "TLS 1.0/1.1", "Deprecated TLS protocol enabled", "Legacy TLS 1.0/1.1 remains offered by the endpoint, exposing clients to downgrade and known cipher weaknesses.", "Disable TLS < 1.2; enforce modern cipher suites."),
]

COUNTRIES = [
    ("Russia", "RU", 55.75, 37.61), ("China", "CN", 39.9, 116.4), ("United States", "US", 38.9, -77.03),
    ("Brazil", "BR", -15.79, -47.88), ("India", "IN", 28.61, 77.2), ("Iran", "IR", 35.69, 51.38),
    ("North Korea", "KP", 39.03, 125.75), ("Nigeria", "NG", 9.07, 7.49), ("Germany", "DE", 52.52, 13.4),
    ("Vietnam", "VN", 21.02, 105.83), ("Netherlands", "NL", 52.37, 4.9), ("Ukraine", "UA", 50.45, 30.52),
]


def _local_ip(sub: int = 1) -> str:
    return f"192.168.{sub}.{_rint(2, 254)}"


def _ext_ip() -> str:
    return f"{random.choice([45,185,193,5,91,103,194,212])}.{_rint(0,255)}.{_rint(0,255)}.{_rint(1,254)}"


def _make_device(dtype: str, i: int) -> Device:
    vendors, oses, fp, host_fn, services = PROFILES[dtype]
    vendor = random.choice(vendors)
    host = host_fn()
    suspicious = _chance(0.8) if dtype == "unknown" else _chance(0.1)
    if dtype == "phone":
        n_svc = 0
    elif dtype == "unknown":
        n_svc = _rint(0, 1) if suspicious else 0
    else:
        n_svc = _rint(1, min(4, len(services)))
    open_ports = random.sample(services, min(n_svc, len(services))) if services else []
    return Device(
        id=uid("dev"), ip=_local_ip(), mac=_mac_for(vendor),
        hostname=host or f"unknown-{i}", type=dtype, vendor=vendor, os=random.choice(oses),
        fingerprint=f"{FP_BY_HOST.get(host, fp)} · {vendor}",
        vlan=30 if dtype in ("iot", "unknown") else (10 if dtype == "server" else 20),
        suspicious=suspicious, lastSeen=now_ms() - _rint(0, 90_000),
        trafficMbps=_rint(0, 60), openPorts=sorted(open_ports), parentId="dev_gateway",
    )


def _make_devices() -> list[Device]:
    gw = Device(
        id="dev_gateway", ip="192.168.1.1", mac=_mac_for("Cisco"), hostname="edge-fw-01",
        type="router", vendor="Cisco", os="Cisco IOS XE 17.9", fingerprint="Gateway / Firewall · Cisco",
        vlan=1, suspicious=False, lastSeen=now_ms(), trafficMbps=_rint(60, 140), openPorts=[22, 53, 161, 443],
    )
    layout = ["server", "server", "pc", "pc", "phone", "iot", "iot", "pc", "unknown", "phone", "server", "iot"]
    devices = [gw]
    for i in range(_rint(9, 12)):
        devices.append(_make_device(layout[i % len(layout)], i))
    return devices


def _make_ports(devices: list[Device]) -> list[Port]:
    ports: list[Port] = []
    for d in devices:
        for port in d.openPorts:
            base = SERVICE_RISK.get(port, "medium")
            ports.append(Port(
                id=uid("port"), port=port, service=SERVICE_NAME.get(port, "unknown"),
                protocol="UDP" if port in (53, 161, 1883) else "TCP",
                risk="medium" if (d.suspicious and base == "low") else base,
                status=random.choices(["open", "filtered", "closed"], weights=[0.82, 0.1, 0.08])[0], host=d.ip,
            ))
    return sorted(ports, key=lambda p: p.port)


def _make_vulns() -> list[Vulnerability]:
    out = []
    for c in CVES:
        published = (datetime.utcnow() - timedelta(days=_rint(30, 900))).date().isoformat()
        out.append(Vulnerability(id=c[0], severity=c[1], cvss=c[2], service=c[3], title=c[4],
                                 description=c[5], remediation=c[6], published=published))
    return out


def _make_geo() -> list[GeoAttack]:
    return [GeoAttack(
        id=uid("geo"), ts=now_ms() - _rint(0, 120_000), country=c[0], countryCode=c[1],
        lat=c[2], lng=c[3], ip=_ext_ip(), count=_rint(1, 40),
        severity=random.choice(["critical", "high", "high", "medium", "low"]),
    ) for c in COUNTRIES[: _rint(6, 10)]]


def _make_timeline() -> list[TimelinePoint]:
    now = now_ms()
    return [TimelinePoint(
        t=now - (30 - i) * 60_000,
        logins=_rint(0, 14) + (_rint(10, 30) if _chance(0.15) else 0), scans=_rint(0, 8),
        suspicious=_rint(0, 6) + (_rint(6, 18) if _chance(0.1) else 0), blocked=_rint(0, 10),
    ) for i in range(30)]


def _score(devices, ports, vulns) -> int:
    susp = sum(1 for d in devices if d.suspicious)
    crit_ports = sum(1 for p in ports if p.risk == "critical" and p.status == "open")
    crit_vulns = sum(1 for v in vulns if v.severity == "critical")
    return min(100, max(6, susp * 6 + crit_ports * 9 + crit_vulns * 12 + _rint(2, 10)))


def make_snapshot() -> Snapshot:
    from . import nvd  # lazy — avoid import cycle / optional httpx

    devices = _try_real_scan() or _make_devices()
    ports = _make_ports(devices)
    vulns = nvd.current_vulns() or _make_vulns()
    geo = _make_geo()
    timeline = _make_timeline()
    score = _score(devices, ports, vulns)
    stats = Stats(
        threatsToday=_rint(18, 140), openPorts=sum(1 for p in ports if p.status == "open"),
        suspiciousIps=sum(1 for d in devices if d.suspicious) + _rint(1, 6), failedLogins=_rint(40, 320),
        activeDevices=len(devices), healthScore=max(20, 100 - round(score * 0.7)), threatScore=score,
    )
    return Snapshot(stats=stats, devices=devices, ports=ports, vulns=vulns, geo=geo, timeline=timeline)


# ── Believable attack scenarios (MITRE ATT&CK) ───────────
def _port_list(d: Device) -> str:
    ps = d.openPorts or [22, 3389, 445]
    return ", ".join(str(p) for p in ps[:3])


def generate_alert(devices: list[Device]) -> Alert | None:
    if not _chance(0.55):
        return None
    internal = [d for d in devices if d.id != "dev_gateway"]
    servers = [d for d in internal if d.type == "server"] or internal
    target = random.choice(servers)
    rogue_pool = [d for d in internal if d.suspicious] or [d for d in internal if d.type == "unknown"] or internal
    rogue = random.choice(rogue_pool)
    attacker = _ext_ip()

    scenarios = [
        ("Port Scan", "high", rogue.ip, rogue.mac,
         f"Unrecognized device {rogue.ip} (MAC vendor: {rogue.vendor}) initiated repeated SYN scans on ports {_port_list(target)} — {_rint(120,400)} probes in {_rint(12,40)}s",
         "Isolate on quarantine VLAN; block MAC at the switchport", "T1046 · Network Service Scanning"),
        ("Brute Force", "critical", attacker, None,
         f"{_rint(180,900)} failed RDP logins on {target.hostname} ({target.ip}:3389) from {attacker} in {_rint(60,180)}s",
         "Block source IP; enforce NLA + account lockout; move RDP behind VPN", "T1110 · Brute Force"),
        ("Exploit Attempt", "critical", rogue.ip, rogue.mac,
         f"SMBv1 exploit pattern (MS17-010 / EternalBlue) targeting {target.ip}:445 from {rogue.ip}",
         "Patch MS17-010; disable SMBv1; contain the source host", "T1210 · Exploitation of Remote Services"),
        ("C2 Beacon", "high", random.choice(internal).ip, None,
         f"Periodic {random.choice([512,1024,256])}-byte beacons to {attacker}:443 every {_rint(30,90)}s — jittered pattern consistent with Cobalt Strike",
         "Block C2 destination; inspect process tree; hunt for the loader", "T1071 · Application Layer Protocol (C2)"),
        ("Data Exfiltration", "high", target.ip, None,
         f"{_rint(4,24)/10:.1f} GB outbound from {target.hostname} ({target.ip}) to {attacker} over {_rint(4,15)}m",
         "Throttle egress; trigger DLP review; snapshot the host for forensics", "T1048 · Exfiltration Over Alternative Protocol"),
        ("DNS Tunneling", "medium", rogue.ip, rogue.mac,
         f"High-entropy DNS queries from {rogue.hostname} ({rogue.ip}) — {_rint(1200,6000)} TXT lookups to *.dnslog.cn",
         "Sinkhole the domain; enforce internal resolver + DNS logging", "T1071.004 · DNS"),
        ("Unknown Device", "medium", rogue.ip, rogue.mac,
         f"Unrecognized device joined VLAN {rogue.vlan}: {rogue.mac} (MAC vendor: {rogue.vendor}), no DHCP hostname",
         "Verify MAC ownership; quarantine until approved via NAC", "T1200 · Hardware Additions"),
        ("Lateral Movement", "high", random.choice(internal).ip, None,
         f"Anomalous admin-share access (PsExec) from {random.choice(internal).hostname} to {target.hostname} ({target.ip})",
         "Reset credentials; review privileged access; enable LSA protection", "T1021.002 · SMB/Windows Admin Shares"),
        ("Exposed Service", "high", rogue.ip, rogue.mac,
         f"Telnet (23) reachable on {rogue.hostname} ({rogue.ip}) from WAN — legacy cleartext administration",
         "Disable Telnet; migrate to SSH; block 23 at the firewall", "T1190 · Exploit Public-Facing Application"),
    ]
    typ, sev, src, mac, msg, act, tech = random.choice(scenarios)
    return Alert(id=uid("alert"), ts=now_ms(), type=typ, severity=sev, message=msg,
                 action=act, technique=tech, source=src, srcMac=mac, ack=False)


def next_timeline_point() -> TimelinePoint:
    return TimelinePoint(
        t=now_ms(), logins=_rint(0, 14) + (_rint(10, 34) if _chance(0.15) else 0), scans=_rint(0, 8),
        suspicious=_rint(0, 6) + (_rint(6, 20) if _chance(0.1) else 0), blocked=_rint(0, 12),
    )


def jitter_stats(s: Stats) -> Stats:
    def j(v, d, lo=0):
        return max(lo, v + round((random.random() - 0.45) * d))
    return Stats(threatsToday=j(s.threatsToday, 3), openPorts=s.openPorts,
                 suspiciousIps=max(0, j(s.suspiciousIps, 2)), failedLogins=j(s.failedLogins, 6),
                 activeDevices=s.activeDevices, healthScore=min(100, j(s.healthScore, 2, 15)),
                 threatScore=min(100, max(5, j(s.threatScore, 3, 5))))


# ── Structured traffic simulation (stateful flows) ───────
def _ephemeral() -> int:
    return _rint(49152, 65535)


class TrafficSimulator:
    """Emits one packet per call, advancing realistic multi-step flows."""

    def __init__(self, devices: list[Device]):
        self.devices = devices
        self.flows: list[dict] = []

    def set_devices(self, devices: list[Device]) -> None:
        self.devices = devices

    def _hosts(self) -> list[Device]:
        return self.devices or [Device(id="x", ip="192.168.1.10", mac="", hostname="h", type="server",
                                       vendor="", os="", fingerprint="", vlan=10, suspicious=False,
                                       lastSeen=0, trafficMbps=0, openPorts=[443])]

    def _spawn(self) -> dict:
        r = random.random()
        if r < 0.1:
            return self._port_scan()
        if r < 0.16:
            return self._beacon()
        if r < 0.20:
            return self._exfil()
        if r < 0.32:
            return self._dns()
        if r < 0.42:
            return self._arp()
        return self._web()

    def _flow(self, src, dst, sport, dport, service, proto, steps) -> dict:
        return {"src": src, "dst": dst, "sport": sport, "dport": dport, "service": service, "proto": proto, "steps": steps, "i": 0}

    def _web(self) -> dict:
        client = random.choice(self._hosts())
        external = _chance(0.6)
        dst = self._ext() if external else random.choice(self._hosts()).ip
        dport = random.choice([443, 443, 80]) if external else (random.choice(random.choice(self._hosts()).openPorts or [443]))
        svc = SERVICE_NAME.get(dport, "HTTPS")
        tls = dport == 443
        steps = [
            ("SYN", 60, "out", "ok", False, "connection open"),
            ("SYN-ACK", 60, "in", "ok", False, "handshake"),
            ("ACK", 52, "out", "ok", False, "established"),
        ]
        if tls:
            steps += [("TLS-ClientHello", _rint(230, 320), "out", "low", False, f"TLSv1.3 → {dst}"),
                      ("TLS-ServerHello", _rint(1200, 1460), "in", "ok", False, "cert exchange")]
        else:
            steps += [("PSH", _rint(300, 620), "out", "low", False, f"GET / {svc}"),
                      ("PSH", _rint(800, 1460), "in", "ok", False, "200 OK")]
        steps.append(("FIN-ACK", 52, "out", "ok", False, "connection close"))
        return self._flow(client.ip, dst, _ephemeral(), dport, svc, "TCP", steps)

    def _dns(self) -> dict:
        client = random.choice(self._hosts())
        q = random.choice(["api.github.com", "cdn.jsdelivr.net", "login.microsoftonline.com", "crl.pki.goog", "ntp.ubuntu.com"])
        steps = [("DNS-Q", _rint(60, 90), "out", "ok", False, f"A? {q}"),
                 ("DNS-R", _rint(90, 160), "in", "ok", False, f"answer {self._ext()}")]
        return self._flow(client.ip, "192.168.1.1", _ephemeral(), 53, "DNS", "UDP", steps)

    def _arp(self) -> dict:
        a, b = random.choice(self._hosts()), random.choice(self._hosts())
        steps = [("ARP-who-has", 42, "out", "ok", False, f"who has {b.ip}?"),
                 ("ARP-is-at", 42, "in", "ok", False, f"{b.ip} is-at {b.mac or '..'}")]
        return self._flow(a.ip, b.ip, 0, 0, "ARP", "ICMP", steps)

    def _port_scan(self) -> dict:
        susp = [d for d in self.devices if d.suspicious]
        attacker = self._ext() if _chance(0.5) else (random.choice(susp).ip if susp else self._ext())
        target = random.choice(self._hosts())
        scan_ports = [21, 22, 23, 80, 135, 139, 443, 445, 3306, 3389, 8080]
        steps = [("SYN", 44, "out", "high", True, f"scan → {target.ip}:{p} ({SERVICE_NAME.get(p,'?')})", p) for p in scan_ports]
        return self._flow(attacker, target.ip, _ephemeral(), scan_ports[0], "SCAN", "TCP", steps)

    def _beacon(self) -> dict:
        host = random.choice(self._hosts())
        c2 = self._ext()
        steps = [("PSH", random.choice([256, 512]), "out", "high", True, f"C2 beacon → {c2}:443") for _ in range(3)]
        return self._flow(host.ip, c2, _ephemeral(), 443, "HTTPS", "TCP", steps)

    def _exfil(self) -> dict:
        servers = [d for d in self._hosts() if d.type == "server"]
        host = random.choice(servers) if servers else random.choice(self._hosts())
        dst = self._ext()
        steps = [("PSH", _rint(1200, 1460), "out", "critical", True, f"bulk transfer → {dst}") for _ in range(4)]
        return self._flow(host.ip, dst, _ephemeral(), random.choice([443, 22, 21]), "HTTPS", "TCP", steps)

    @staticmethod
    def _ext() -> str:
        return _ext_ip()

    def next(self) -> PacketEvent:
        if not self.flows or _chance(0.4):
            self.flows.append(self._spawn())
        idx = _rint(0, len(self.flows) - 1)
        f = self.flows[idx]
        step = f["steps"][f["i"]]
        flags, byts, direction, risk, flagged, info = step[:6]
        dport = step[6] if len(step) > 6 else f["dport"]
        f["i"] += 1
        if f["i"] >= len(f["steps"]):
            self.flows.pop(idx)
        if len(self.flows) > 20:
            self.flows.pop(0)
        outbound = direction == "out"
        return PacketEvent(
            id=uid("pkt"), ts=now_ms(),
            srcIp=f["src"] if outbound else f["dst"], dstIp=f["dst"] if outbound else f["src"],
            srcPort=f["sport"] if outbound else dport, dstPort=dport if outbound else f["sport"],
            protocol=f["proto"], kind=flags, service=f["service"], bytes=byts, info=info, risk=risk, flagged=flagged,
        )


# ── Best-effort real Nmap scan ───────────────────────────
def _try_real_scan() -> list[Device] | None:
    if not settings.scan_enabled:
        return None
    try:
        import nmap  # type: ignore
        scanner = nmap.PortScanner()
        scanner.scan(hosts=settings.scan_target, arguments="-sn")
        devices: list[Device] = []
        for host in scanner.all_hosts():
            devices.append(Device(
                id=uid("dev"), ip=host, mac=_mac_for("Shenzhen Bilian"),
                hostname=scanner[host].hostname() or host, type="unknown", vendor="Unknown",
                os="—", fingerprint="Discovered host · Nmap", vlan=20, suspicious=False,
                lastSeen=now_ms(), trafficMbps=0, openPorts=[],
                parentId=None if host.endswith(".1") else "dev_gateway",
            ))
        return devices or None
    except Exception:
        return None
