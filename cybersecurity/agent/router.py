"""
agent/router.py — SOAR severity router.

Maps triage verdict severity to SOAR actions and ticket creation.
HIGH+ alerts trigger automated response; LOW/MEDIUM are logged.
"""

from __future__ import annotations
from config import AUTO_RESPOND_THRESHOLD, SEVERITY_LEVELS

_SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITY_LEVELS)}
_THRESHOLD_IDX  = _SEVERITY_ORDER.get(AUTO_RESPOND_THRESHOLD, 2)


def route_verdict(verdict: dict) -> dict:
    """
    Enrich a triage verdict with SOAR routing metadata.

    Adds:
      soar_action : "AUTO_RESPOND" | "LOG_AND_MONITOR" | "HUMAN_REVIEW"
      soar_ticket : ticket ID for AUTO_RESPOND cases
      soar_sla    : response SLA string
    """
    severity    = verdict.get("severity", "LOW")
    severity_idx = _SEVERITY_ORDER.get(severity, 0)

    sla_map = {
        "CRITICAL":     "Immediate (< 15 min)",
        "HIGH":         "1 hour",
        "MEDIUM":       "24 hours",
        "LOW":          "Best effort",
        "HUMAN_REVIEW": "Analyst queue",
    }

    if severity == "HUMAN_REVIEW":
        verdict["soar_action"] = "HUMAN_REVIEW"
        verdict["soar_sla"]    = sla_map["HUMAN_REVIEW"]
    elif severity_idx >= _THRESHOLD_IDX:
        alert_id = verdict.get("alert_id", "UNKNOWN")
        verdict["soar_action"] = "AUTO_RESPOND"
        verdict["soar_ticket"] = f"SOAR-AUTO-{alert_id}"
        verdict["soar_sla"]    = sla_map.get(severity, "1 hour")
    else:
        verdict["soar_action"] = "LOG_AND_MONITOR"
        verdict["soar_sla"]    = sla_map.get(severity, "24 hours")

    return verdict
