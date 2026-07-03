"""Pydantic schemas — mirror the frontend TypeScript types in src/lib/types.ts."""
from __future__ import annotations

from typing import Literal, Optional
from pydantic import BaseModel

Severity = Literal["critical", "high", "medium", "low", "ok"]
DeviceType = Literal["router", "server", "pc", "phone", "iot", "unknown"]
PortStatus = Literal["open", "filtered", "closed"]
Protocol = Literal["TCP", "UDP", "ICMP"]


class Stats(BaseModel):
    threatsToday: int
    openPorts: int
    suspiciousIps: int
    failedLogins: int
    activeDevices: int
    healthScore: int
    threatScore: int


class Device(BaseModel):
    id: str
    ip: str
    mac: str
    hostname: str
    type: DeviceType
    vendor: str
    os: str
    fingerprint: str
    vlan: int
    suspicious: bool
    lastSeen: int
    trafficMbps: int
    openPorts: list[int] = []
    parentId: Optional[str] = None


class Port(BaseModel):
    id: str
    port: int
    service: str
    status: PortStatus
    protocol: Protocol
    risk: Severity
    host: str


class PacketEvent(BaseModel):
    id: str
    ts: int
    srcIp: str
    dstIp: str
    srcPort: int
    dstPort: int
    protocol: Protocol
    kind: str
    service: str
    bytes: int
    info: str
    risk: Severity
    flagged: bool


class Vulnerability(BaseModel):
    id: str
    severity: Severity
    cvss: float
    service: str
    title: str
    description: str
    remediation: str
    published: str


class Alert(BaseModel):
    id: str
    ts: int
    type: str
    severity: Severity
    message: str
    action: str
    technique: Optional[str] = None
    source: Optional[str] = None
    srcMac: Optional[str] = None
    ack: bool = False


class GeoAttack(BaseModel):
    id: str
    ts: int
    country: str
    countryCode: str
    lat: float
    lng: float
    ip: str
    count: int
    severity: Severity


class TimelinePoint(BaseModel):
    t: int
    logins: int
    scans: int
    suspicious: int
    blocked: int


class Snapshot(BaseModel):
    stats: Stats
    devices: list[Device]
    ports: list[Port]
    vulns: list[Vulnerability]
    geo: list[GeoAttack]
    timeline: list[TimelinePoint]


# ── Auth / AI ────────────────────────────────────────────
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


class ExplainRequest(BaseModel):
    question: str
    context: dict


class ExplainResponse(BaseModel):
    answer: str
    live: bool  # True when produced by Claude, False for the heuristic fallback


class EventRecord(BaseModel):
    id: int
    ts: int
    type: str
    severity: Severity
    message: str
    action: Optional[str] = None
    technique: Optional[str] = None
    source: Optional[str] = None
    srcMac: Optional[str] = None
