"""
agent/guardrails.py — Pre-flight and post-flight safety checks.

Pre-flight:  check_prompt_injection(text) — raises ValueError on injection attempt.
Post-flight: run_all_postflight(verdict)  — confidence gating, severity validation.
"""

from __future__ import annotations
from config import INJECTION_KEYWORDS, CONFIDENCE_THRESHOLD, SEVERITY_LEVELS


def check_prompt_injection(text: str) -> None:
    """
    Scan alert text for known prompt injection patterns.
    Raises ValueError if injection is detected, causing the agent
    to return a HUMAN_REVIEW verdict instead of processing the alert.
    """
    text_lower = text.lower()
    for keyword in INJECTION_KEYWORDS:
        if keyword.lower() in text_lower:
            raise ValueError(
                f"Prompt injection attempt detected: '{keyword}'. Alert quarantined."
            )


def _validate_severity(verdict: dict) -> dict:
    """Ensure severity is a known value; fallback to HUMAN_REVIEW."""
    severity = verdict.get("severity", "")
    if severity not in SEVERITY_LEVELS and severity != "HUMAN_REVIEW":
        verdict["severity"] = "HUMAN_REVIEW"
        verdict["guardrail_triggered"] = True
        verdict["guardrail_reason"]    = f"Unknown severity value: '{severity}'"
    return verdict


def _confidence_gate(verdict: dict) -> dict:
    """Route to HUMAN_REVIEW if confidence is below threshold."""
    confidence = verdict.get("confidence", 1.0)
    if isinstance(confidence, (int, float)) and confidence < CONFIDENCE_THRESHOLD:
        verdict["severity"]           = "HUMAN_REVIEW"
        verdict["guardrail_triggered"] = True
        verdict["guardrail_reason"]   = (
            f"Confidence {confidence:.0%} below threshold {CONFIDENCE_THRESHOLD:.0%}. "
            "Manual analyst review required."
        )
    return verdict


def _ensure_required_fields(verdict: dict) -> dict:
    """Add default values for any missing required output fields."""
    verdict.setdefault("recommended_actions", ["Review alert manually"])
    verdict.setdefault("mitre_techniques",    [])
    verdict.setdefault("grounding_sources",   [])
    verdict.setdefault("guardrail_triggered", False)
    return verdict


def run_all_postflight(verdict: dict) -> dict:
    """
    Run all post-flight guardrails on the agent verdict.
    Order: validate severity → confidence gate → fill defaults → log checks.
    Sets guardrails_checked=True and guardrails_log so callers can confirm
    guardrails ran even when nothing triggered.
    """
    checks_run = []

    # 1. Severity validation
    original_severity = verdict.get("severity", "")
    verdict = _validate_severity(verdict)
    if verdict.get("severity") != original_severity:
        checks_run.append(f"severity_invalid({original_severity!r}->HUMAN_REVIEW)")
    else:
        checks_run.append(f"severity_ok({original_severity!r})")

    # 2. Confidence gate
    confidence = verdict.get("confidence", 1.0)
    verdict = _confidence_gate(verdict)
    if verdict.get("guardrail_triggered") and "below threshold" in verdict.get("guardrail_reason", ""):
        checks_run.append(f"confidence_low({confidence:.0%}<{CONFIDENCE_THRESHOLD:.0%}->HUMAN_REVIEW)")
    else:
        checks_run.append(f"confidence_ok({confidence:.0%}>={CONFIDENCE_THRESHOLD:.0%})")

    # 3. Fill defaults
    verdict = _ensure_required_fields(verdict)

    # 4. Observability — always record that guardrails ran
    verdict["guardrails_checked"] = True
    verdict["guardrails_log"]     = checks_run

    return verdict
