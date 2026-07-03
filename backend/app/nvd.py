"""Live NVD (NIST National Vulnerability Database) CVE feed.

Pulls recent CVEs from the NVD 2.0 API, maps them to our Vulnerability schema,
and caches them in memory. The telemetry engine uses this cache when populated
and falls back to the curated real-CVE set otherwise, so the app works offline.

Docs: https://nvd.nist.gov/developers/vulnerabilities
An API key (SOC_NVD_API_KEY / NVD_API_KEY) is optional but raises rate limits.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta

from .config import settings
from .schemas import Severity, Vulnerability

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_cache: list[Vulnerability] = []
_last_ok: bool = False


def current_vulns() -> list[Vulnerability]:
    """Return the cached live CVEs (empty list until the first successful fetch)."""
    return list(_cache)


def is_live() -> bool:
    return _last_ok


def _severity_from(score: float) -> Severity:
    # CVSS v3 bands (v2 has no "critical", so derive from the score, not the label).
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _affected_service(cve: dict) -> str:
    """Derive a readable 'vendor product' label from the first CPE match."""
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for match in node.get("cpeMatch", []):
                parts = match.get("criteria", "").split(":")
                if len(parts) > 5:
                    vendor = parts[3].replace("_", " ")
                    product = parts[4].replace("_", " ")
                    ver = parts[5] if parts[5] not in ("*", "-") else ""
                    return f"{vendor} {product} {ver}".strip().title()
    return "See NVD advisory"


def _map(item: dict) -> Vulnerability | None:
    cve = item.get("cve", {})
    cid = cve.get("id")
    if not cid:
        return None
    descs = cve.get("descriptions", [])
    desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
    metrics = cve.get("metrics", {})
    m = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or metrics.get("cvssMetricV2") or []
    if not m:
        return None
    data = m[0].get("cvssData", {})
    score = float(data.get("baseScore", 0.0))
    sev = _severity_from(score)

    title = desc.strip().split(". ")[0][:110] or cid
    ref = next((r["url"] for r in cve.get("references", []) if r.get("url")), None)
    remediation = f"Review the NVD advisory and apply vendor patches. {ref}" if ref else "Review the NVD advisory and apply vendor patches; restrict exposure of the affected service."
    return Vulnerability(
        id=cid, severity=sev, cvss=round(score, 1), service=_affected_service(cve),
        title=title, description=desc[:280], remediation=remediation[:200],
        published=(cve.get("published") or "")[:10],
    )


async def refresh(limit: int = 12) -> bool:
    """Fetch recent CVEs from NVD into the cache. Returns True on success.

    Warm-starts from Redis when available to avoid redundant NIST API calls.
    """
    global _cache, _last_ok
    if not settings.nvd_enabled:
        return False

    from . import cache

    cached = await cache.get_json("nvd:vulns")
    if cached:
        try:
            _cache = [Vulnerability(**v) for v in cached][:limit]
            _last_ok = True
            return True
        except Exception:
            pass

    try:
        import httpx

        headers = {}
        key = settings.nvd_api_key or os.environ.get("NVD_API_KEY")
        if key:
            headers["apiKey"] = key
        # Recent advisories: published in the last 30 days (NVD requires both bounds,
        # ≤120-day range). Default sort is oldest-first, so we filter by date then
        # rank by CVSS ourselves.
        end = datetime.utcnow()
        start = end - timedelta(days=30)
        fmt = "%Y-%m-%dT%H:%M:%S.000"
        params = {
            "pubStartDate": start.strftime(fmt),
            "pubEndDate": end.strftime(fmt),
            "resultsPerPage": 200,
            "noRejected": "",
        }
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(NVD_URL, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        mapped = [v for v in (_map(it) for it in data.get("vulnerabilities", [])) if v]
        # Prefer the highest-severity, most-recent advisories.
        mapped.sort(key=lambda v: (v.cvss, v.published), reverse=True)
        if mapped:
            _cache = mapped[:limit]
            _last_ok = True
            await cache.set_json("nvd:vulns", [v.model_dump() for v in _cache], ttl=int(settings.nvd_refresh_hours * 3600))
            return True
        return False
    except Exception:
        _last_ok = False
        return False  # leave cache as-is → telemetry uses the curated fallback
