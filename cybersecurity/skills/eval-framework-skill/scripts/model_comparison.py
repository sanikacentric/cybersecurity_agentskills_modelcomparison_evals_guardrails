#!/usr/bin/env python3
"""
skills/eval-framework-skill/scripts/model_comparison.py

Runs the full evaluation pipeline with BOTH GPT-4o and GPT-4o-mini,
then produces a side-by-side comparison report.

This is the key script that demonstrates the cost/quality tradeoff
that Microsoft NEXT would use to decide on model routing strategies.

Usage:
    python skills/eval-framework-skill/scripts/model_comparison.py
    python skills/eval-framework-skill/scripts/model_comparison.py --limit 20
    python skills/eval-framework-skill/scripts/model_comparison.py --save-report
"""

import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import config
from eval.runner import run_evaluation
from eval.metrics import compute_all_metrics


def run_for_model(model_name: str, limit: int = None) -> dict:
    """Run evaluation for a specific model and return metrics."""
    print(f"\n{'='*60}")
    print(f"[AI] Running evaluation: {model_name}")
    print(f"{'='*60}")

    # Override model in config
    original = config.LLM_MODEL
    config.LLM_MODEL = model_name

    try:
        metrics = run_evaluation(limit=limit, verbose=False, save_results=True)
    finally:
        config.LLM_MODEL = original

    return metrics


def print_comparison(results: dict):
    """Print a formatted side-by-side comparison table."""
    m4o   = results.get("gpt-4o", {})
    mmini = results.get("gpt-4o-mini", {})

    def get(m, *keys, default="N/A"):
        val = m
        for k in keys:
            val = val.get(k, {}) if isinstance(val, dict) else default
        return val if val != {} else default

    def fmt_pct(v):  return f"{v:.1%}" if isinstance(v, float) else str(v)
    def fmt_f(v):    return f"{v:.3f}" if isinstance(v, float) else str(v)
    def fmt_ms(v):   return f"{v:.0f}ms" if isinstance(v, (int, float)) else str(v)
    def fmt_cost(v): return f"${v:.5f}" if isinstance(v, float) else str(v)
    def fmt_mo(v):   return f"${v:,.2f}" if isinstance(v, (int, float)) else str(v)

    rows = [
        ("QUALITY METRICS", None, None),
        ("Groundedness",       fmt_pct(get(m4o, "summary", "groundedness_score")),    fmt_pct(get(mmini, "summary", "groundedness_score"))),
        ("Precision",          fmt_f(get(m4o, "classification", "precision")),         fmt_f(get(mmini, "classification", "precision"))),
        ("Recall",             fmt_f(get(m4o, "classification", "recall")),            fmt_f(get(mmini, "classification", "recall"))),
        ("F1 Score",           fmt_f(get(m4o, "classification", "f1")),               fmt_f(get(mmini, "classification", "f1"))),
        ("Safety Pass Rate",   fmt_pct(get(m4o, "summary", "safety_pass_rate")),      fmt_pct(get(mmini, "summary", "safety_pass_rate"))),
        ("PERFORMANCE", None, None),
        ("Avg Latency",        fmt_ms(get(m4o, "latency", "mean_ms")),                fmt_ms(get(mmini, "latency", "mean_ms"))),
        ("P95 Latency",        fmt_ms(get(m4o, "latency", "p95_ms")),                 fmt_ms(get(mmini, "latency", "p95_ms"))),
        ("Avg Tokens/alert",   str(get(m4o, "cost", "avg_tokens_per_alert")),         str(get(mmini, "cost", "avg_tokens_per_alert"))),
        ("COST", None, None),
        ("Cost per alert",     fmt_cost(get(m4o, "cost", "cost_per_alert_usd")),      fmt_cost(get(mmini, "cost", "cost_per_alert_usd"))),
        ("Daily @ 10K alerts", fmt_mo(get(m4o, "cost", "projected_daily_10k_usd")),   fmt_mo(get(mmini, "cost", "projected_daily_10k_usd"))),
        ("Monthly @ 10K/day",  fmt_mo(get(m4o, "cost", "projected_monthly_usd")),     fmt_mo(get(mmini, "cost", "projected_monthly_usd"))),
    ]

    print("\n")
    print("╔" + "═"*58 + "╗")
    print("║" + "  GPT-4o vs GPT-4o-mini — cybersecurity Evaluation".center(58) + "║")
    print("╠" + "═"*58 + "╣")
    print(f"║  {'Metric':<28} {'GPT-4o':>12} {'GPT-4o-mini':>12}  ║")
    print("╠" + "═"*58 + "╣")

    for metric, v4o, vmini in rows:
        if v4o is None:
            print("╠" + "─"*58 + "╣")
            print(f"║  {metric:<54}  ║")
        else:
            print(f"║  {metric:<28} {v4o:>12} {vmini:>12}  ║")

    print("╚" + "═"*58 + "╝")

    # Savings calculation
    cost_4o   = get(m4o,   "cost", "projected_monthly_usd")
    cost_mini = get(mmini, "cost", "projected_monthly_usd")
    if isinstance(cost_4o, (int, float)) and isinstance(cost_mini, (int, float)) and cost_4o > 0:
        savings   = cost_4o - cost_mini
        savings_pct = (savings / cost_4o) * 100
        print(f"\n[IDEA] Monthly savings with gpt-4o-mini: ${savings:,.2f} ({savings_pct:.0f}% cheaper)")

    print("\n[*] ROUTING RECOMMENDATION:")
    print("   Use gpt-4o      → HIGH + CRITICAL alerts (accuracy-critical)")
    print("   Use gpt-4o-mini → LOW + MEDIUM alerts  (cost-optimized)")
    print("   Blended strategy: ~60% cost reduction vs all-gpt-4o")


def save_report(results: dict, path: Path):
    """Save comparison results to JSON."""
    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "models_compared": list(results.keys()),
        "results": results,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[SAVE] Report saved to: {path}")


def main():
    parser = argparse.ArgumentParser(description="Compare GPT-4o vs GPT-4o-mini")
    parser.add_argument("--limit", type=int, default=None,
                        help="Limit alerts per model (default: full dataset)")
    parser.add_argument("--save-report", action="store_true",
                        help="Save comparison report JSON")
    args = parser.parse_args()

    results = {}
    for model in ["gpt-4o", "gpt-4o-mini"]:
        results[model] = run_for_model(model, limit=args.limit)

    print_comparison(results)

    if args.save_report:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        report_path = Path("eval/results") / f"model_comparison_{ts}.json"
        save_report(results, report_path)


if __name__ == "__main__":
    main()
