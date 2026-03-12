#!/usr/bin/env python3
"""
skills/soc-triage-skill/scripts/triage_alert.py

Main triage script executed by the SOC Triage Skill.
Supports both GPT-4o (accuracy) and GPT-4o-mini (cost/speed).
Can run side-by-side model comparisons.

Usage:
    python skills/soc-triage-skill/scripts/triage_alert.py --demo
    python skills/soc-triage-skill/scripts/triage_alert.py --demo --model gpt-4o-mini
    python skills/soc-triage-skill/scripts/triage_alert.py --demo --compare-models
    python skills/soc-triage-skill/scripts/triage_alert.py --file alert.json
"""

import sys
import json
import argparse
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))


DEMO_ALERT = {
    "alert_id": "DEMO-001",
    "type": "suspicious_login",
    "user": "john.doe@company.com",
    "source_ip": "185.220.101.45",
    "location": "Romania",
    "prev_location": "New York, USA",
    "time_gap_hours": 2.0,
    "timestamp": "2024-01-15T03:14:00Z"
}


def run_triage(alert: dict, model: str) -> dict:
    """Run the SecurityAgent on an alert with the specified model."""
    # Temporarily override the model in config
    import config
    original_model = config.LLM_MODEL
    config.LLM_MODEL = model

    try:
        from agent.agent import SecurityAgent
        agent = SecurityAgent()
        result = agent.analyze(alert)
        result["model_used"] = model
        return result
    finally:
        config.LLM_MODEL = original_model


def print_verdict(result: dict, label: str = ""):
    """Pretty-print a triage result."""
    header = f"{'='*60}"
    if label:
        print(f"\n{header}")
        print(f"  [AI] MODEL: {label}")
    print(header)

    severity_icons = {
        "CRITICAL": "[!!!]", "HIGH": "[STOP]", "MEDIUM": "[WARN]",
        "LOW": "[GO]", "HUMAN_REVIEW": "⚪"
    }
    severity = result.get("severity", "UNKNOWN")
    icon = severity_icons.get(severity, "❓")

    print(f"{icon} SEVERITY:    {severity}")
    print(f"[CHART] CONFIDENCE:  {result.get('confidence', 0):.0%}")
    print(f"⏱️  LATENCY:     {result.get('latency_ms', 0)}ms")
    print(f"[*]  TOKENS:      {result.get('tokens_used', 0)}")

    cost = result.get("tokens_used", 0) * (
        0.000005 if result.get("model_used", "").endswith("mini") else 0.000015
    )
    print(f"[$] EST. COST:   ${cost:.5f}")
    print(f"\n[NOTE] EXPLANATION:\n   {result.get('explanation', 'N/A')}")

    actions = result.get("recommended_actions", [])
    if actions:
        print(f"\n[FAST] ACTIONS:")
        for a in actions:
            print(f"   • {a}")

    sources = result.get("grounding_sources", [])
    if sources:
        print(f"\n[*] SOURCES: {', '.join(sources)}")

    mitre = result.get("mitre_techniques", [])
    if mitre:
        print(f"[!] MITRE:   {', '.join(mitre)}")

    if result.get("guardrail_triggered"):
        print(f"\n[WARN]️  GUARDRAIL: {result.get('guardrail_reason', 'Triggered')}")

    print(header)


def compare_models(alert: dict):
    """Run the same alert through both models and compare results."""
    print("\n[*] MODEL COMPARISON: GPT-4o vs GPT-4o-mini")
    print("="*60)
    print(f"Alert: {alert.get('alert_id')} | Type: {alert.get('type')}")

    results = {}
    for model in ["gpt-4o", "gpt-4o-mini"]:
        print(f"\n⏳ Running {model}...")
        results[model] = run_triage(alert, model)
        print_verdict(results[model], label=model)

    # Side-by-side comparison summary
    r4o = results["gpt-4o"]
    r4o_mini = results["gpt-4o-mini"]

    cost_4o = r4o.get("tokens_used", 0) * 0.000015
    cost_mini = r4o_mini.get("tokens_used", 0) * 0.000005
    savings_pct = ((cost_4o - cost_mini) / max(cost_4o, 0.0001)) * 100

    print("\n" + "="*60)
    print("[CHART] COMPARISON SUMMARY")
    print("="*60)
    print(f"{'Metric':<25} {'GPT-4o':>15} {'GPT-4o-mini':>15}")
    print("-"*55)
    print(f"{'Severity':<25} {r4o.get('severity','?'):>15} {r4o_mini.get('severity','?'):>15}")
    print(f"{'Confidence':<25} {r4o.get('confidence',0):>14.0%} {r4o_mini.get('confidence',0):>14.0%}")
    print(f"{'Latency (ms)':<25} {r4o.get('latency_ms',0):>15} {r4o_mini.get('latency_ms',0):>15}")
    print(f"{'Tokens used':<25} {r4o.get('tokens_used',0):>15} {r4o_mini.get('tokens_used',0):>15}")
    print(f"{'Est. cost ($)':<25} {cost_4o:>15.5f} {cost_mini:>15.5f}")
    print(f"{'Match on severity?':<25} {'—':>15} {'[OK] YES' if r4o.get('severity')==r4o_mini.get('severity') else '[X] NO':>15}")
    print(f"\n[IDEA] Cost savings with gpt-4o-mini: {savings_pct:.0f}%")
    print("="*60)

    return results


def main():
    parser = argparse.ArgumentParser(description="cybersecurity SOC Triage")
    parser.add_argument("--demo", action="store_true", help="Run demo alert")
    parser.add_argument("--file", type=str, help="Path to alert JSON file")
    parser.add_argument("--model", default="gpt-4o",
                        choices=["gpt-4o", "gpt-4o-mini"],
                        help="LLM model (default: gpt-4o)")
    parser.add_argument("--compare-models", action="store_true",
                        help="Run side-by-side GPT-4o vs GPT-4o-mini comparison")
    args = parser.parse_args()

    # Load alert
    if args.file:
        with open(args.file) as f:
            alert = json.load(f)
    elif args.demo:
        alert = DEMO_ALERT
    else:
        print("Error: provide --demo or --file <path>")
        parser.print_help()
        sys.exit(1)

    print(f"\n[S]️  cybersecurity SOC Triage")
    print(f"Alert ID: {alert.get('alert_id')} | Type: {alert.get('type')}")

    if args.compare_models:
        compare_models(alert)
    else:
        print(f"Model: {args.model}\n")
        result = run_triage(alert, args.model)
        print_verdict(result)

        # Also print raw JSON
        print("\n[*] RAW JSON OUTPUT:")
        print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
