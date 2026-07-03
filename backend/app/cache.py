"""Redis cache (via redis.asyncio).

Used to warm-start / rate-limit the live NVD feed across restarts. Optional:
if REDIS_URL is unset or Redis is unreachable, every function is a safe no-op.
"""
from __future__ import annotations

import json
from typing import Any

from .config import settings

_client: Any = None


async def connect() -> None:
    global _client
    if not settings.redis_url:
        return
    try:
        import redis.asyncio as redis

        _client = redis.from_url(settings.redis_url, socket_connect_timeout=5, decode_responses=True)
        await _client.ping()
    except Exception:
        _client = None


async def close() -> None:
    global _client
    if _client is not None:
        try:
            await _client.aclose()
        finally:
            _client = None


def available() -> bool:
    return _client is not None


async def get_json(key: str) -> Any | None:
    if _client is None:
        return None
    try:
        raw = await _client.get(key)
        return json.loads(raw) if raw else None
    except Exception:
        return None


async def set_json(key: str, value: Any, ttl: int = 3600) -> None:
    if _client is None:
        return
    try:
        await _client.set(key, json.dumps(value), ex=ttl)
    except Exception:
        pass
