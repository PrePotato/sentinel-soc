"""AI threat-explanation service, backed by Claude (Anthropic SDK).

Uses a fast, cheap summarization model (Haiku 4.5 by default — override with
SOC_AI_MODEL). Falls back to a local heuristic analyst when no API key is
configured, so the endpoint always returns something useful.
"""
from __future__ import annotations

import json
import os

from .config import settings
from .schemas import ExplainResponse

SYSTEM_PROMPT = (
    "You are SENTINEL, a senior SOC (Security Operations Center) analyst. "
    "You are given a JSON snapshot of live security telemetry from a monitored network "
    "(threat score, open alerts, risky open ports, top CVEs, suspicious devices). "
    "Answer the operator's question clearly and concisely for a technical audience. "
    "Explain WHY something is dangerous, then give concrete, prioritized mitigation steps "
    "as short bullet points. Ground every claim in the provided telemetry. "
    "Keep the whole answer under ~180 words. Do not invent data that is not present."
)


def _has_key() -> bool:
    return bool(settings.anthropic_api_key or os.environ.get("ANTHROPIC_API_KEY"))


def explain(question: str, context: dict) -> ExplainResponse:
    if not _has_key():
        return ExplainResponse(answer=_local_explain(question, context), live=False)
    try:
        import anthropic

        client = anthropic.Anthropic(api_key=settings.anthropic_api_key) if settings.anthropic_api_key else anthropic.Anthropic()
        user_content = (
            f"Live telemetry snapshot:\n```json\n{json.dumps(context, indent=2)[:6000]}\n```\n\n"
            f"Operator question: {question}"
        )
        # Haiku 4.5: plain messages.create — no `thinking`/`effort` (Haiku rejects effort).
        msg = client.messages.create(
            model=settings.ai_model,
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_content}],
        )
        text = "".join(b.text for b in msg.content if getattr(b, "type", None) == "text").strip()
        return ExplainResponse(answer=text or _local_explain(question, context), live=True)
    except Exception:
        # Missing key, network error, or refusal → heuristic fallback.
        return ExplainResponse(answer=_local_explain(question, context), live=False)


def _local_explain(q: str, ctx: dict) -> str:
    ql = q.lower()
    ports = ctx.get("riskyOpenPorts", []) or []
    vulns = ctx.get("topVulnerabilities", []) or []
    suspicious = ctx.get("suspiciousDevices", []) or []
    alerts = ctx.get("openAlerts", []) or []
    score = ctx.get("threatScore", "—")
    health = ctx.get("healthScore", "—")

    if "telnet" in ql or "23" in ql or "port" in ql:
        return (
            "Telnet (TCP/23) sends credentials and session data in cleartext, so anyone on the "
            "path can capture logins with a passive sniffer. It has no encryption and is a prime "
            "target for IoT botnets brute-forcing default creds.\n\n"
            "Mitigation:\n"
            "• Disable Telnet; use SSH (TCP/22) with key-based auth.\n"
            "• If a legacy device needs it, isolate it on a management VLAN with no internet route.\n"
            "• Add an IDS signature for inbound 23 and alert on external attempts."
        )

    if "prioriti" in ql or "first" in ql or "what should" in ql:
        lines = ["Prioritise in this order based on current telemetry:"]
        if ports:
            lines.append(f"1. Close/segment {len(ports)} high-risk open port(s) — e.g. {ports[0]}.")
        if vulns:
            lines.append(f"2. Patch critical CVEs — {vulns[0]}.")
        if suspicious:
            lines.append(f"3. Quarantine {len(suspicious)} suspicious device(s): {', '.join(suspicious[:3])}.")
        if alerts:
            lines.append(f"4. Work the {len(alerts)} open alert(s), criticals first.")
        lines.append(f"\nThreat score {score}/100, system health {health}/100.")
        return "\n".join(lines)

    if "alert" in ql:
        if not alerts:
            return "There are no open alerts right now — the environment is quiet. Keep the packet feed and geo map under observation."
        body = "\n".join(f"{i+1}. {a}" for i, a in enumerate(alerts))
        return f"Open alerts requiring attention:\n\n{body}\n\nAcknowledge each after triage; escalate brute-force or exfiltration alerts to IR immediately."

    top = (alerts or ports or vulns or ["no active threats detected"])[0]
    return (
        f"Highest-signal item: {top}.\n\n"
        f"Threat score {score}/100. {len(suspicious)} suspicious device(s), {len(ports)} risky open port(s), {len(vulns)} notable CVE(s).\n\n"
        "Recommended next step: contain the source (block IP / isolate device), confirm scope in the packet feed, then remediate the exposure.\n\n"
        "(Offline analyst — set ANTHROPIC_API_KEY to enable full Claude-powered analysis.)"
    )
