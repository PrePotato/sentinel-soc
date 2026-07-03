"""WebSocket broadcaster + background telemetry engine.

Every connected client first receives a full `snapshot`, then a live stream of
`packet`, `alert`, `timeline`, and `stats` messages — the same envelope shape
the frontend's useLiveFeed hook consumes.
"""
from __future__ import annotations

import asyncio
import random

from fastapi import WebSocket

from . import db
from . import telemetry as T
from .config import settings
from .schemas import Snapshot, Stats


class Engine:
    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()
        self.snapshot: Snapshot = T.make_snapshot()
        self.stats: Stats = self.snapshot.stats
        self.sim = T.TrafficSimulator(self.snapshot.devices)
        self._tasks: list[asyncio.Task] = []

    # ── client lifecycle ────────────────────────────────
    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.clients.add(ws)
        # Hydrate the newcomer with the current world.
        await self._send(ws, "snapshot", self.snapshot.model_dump())

    def disconnect(self, ws: WebSocket) -> None:
        self.clients.discard(ws)

    async def _send(self, ws: WebSocket, type_: str, payload) -> bool:
        try:
            await ws.send_json({"type": type_, "payload": payload})
            return True
        except Exception:
            return False

    async def broadcast(self, type_: str, payload) -> None:
        dead = [ws for ws in self.clients if not await self._send(ws, type_, payload)]
        for ws in dead:
            self.disconnect(ws)

    # ── background loops ────────────────────────────────
    def start(self) -> None:
        if self._tasks:
            return
        self._tasks = [
            asyncio.create_task(self._packets()),
            asyncio.create_task(self._alerts()),
            asyncio.create_task(self._timeline()),
            asyncio.create_task(self._stats()),
            asyncio.create_task(self._nvd()),
        ]

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        self._tasks = []

    async def _packets(self) -> None:
        while True:
            await asyncio.sleep(settings.broadcast_interval * 0.75)
            if self.clients:
                self.sim.set_devices(self.snapshot.devices)
                await self.broadcast("packet", self.sim.next().model_dump())

    async def _alerts(self) -> None:
        while True:
            await asyncio.sleep(4.2)
            alert = T.generate_alert(self.snapshot.devices)
            if alert:
                await db.log_event(alert)  # persist to the searchable event log (if DB present)
                if self.clients:
                    await self.broadcast("alert", alert.model_dump())

    async def _nvd(self) -> None:
        """Pull the live NVD CVE feed on startup and on an interval; rebroadcast."""
        from . import nvd

        await asyncio.sleep(1.0)
        while True:
            if await nvd.refresh():
                self.snapshot.vulns = nvd.current_vulns()
                if self.clients:
                    await self.broadcast("snapshot", self.snapshot.model_dump())
            await asyncio.sleep(max(300.0, settings.nvd_refresh_hours * 3600))

    async def _timeline(self) -> None:
        while True:
            await asyncio.sleep(5.0)
            if self.clients:
                await self.broadcast("timeline", T.next_timeline_point().model_dump())

    async def _stats(self) -> None:
        while True:
            await asyncio.sleep(3.0)
            self.stats = T.jitter_stats(self.stats)
            self.snapshot.stats = self.stats
            if self.clients:
                await self.broadcast("stats", self.stats.model_dump())

    def rescan(self) -> Snapshot:
        """Regenerate the environment (manual scan)."""
        self.snapshot = T.make_snapshot()
        self.stats = self.snapshot.stats
        self.sim.set_devices(self.snapshot.devices)
        return self.snapshot


engine = Engine()
