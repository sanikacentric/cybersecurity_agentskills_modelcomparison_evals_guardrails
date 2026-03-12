"""
eval/runner.py — Batch evaluation runner.

Loads the synthetic alert dataset, runs each alert through the SecurityAgent,
and computes full metrics. Supports model override and result persistence.

Usage:
    python -m eval.runner
    python -m eval.runner --model gpt-4o-mini --limit 20
"""

from __future__ import annotations
import json
import argparse
from datetime import datetime
from pathlib import Path

import config
from config import EVAL_DATASET_PATH, EVAL_RESULTS_DIR
from eval.metrics import compute_all_metrics


def _load_dataset(path: Path) -> list[dict]:
    if not path.exists():
        raise FileNotFoundError(
            f"Dataset not found: {path}\n"
            "Run: python -m eval.dataset_builder"
        )
    with open(path) as f:
        return json.load(f)


def run_evaluation(
    dataset_path: Path = None,
    model:        str  = None,
    limit:        int  = None,
    verbose:      bool = True,
    save_results: bool = True,
) -> dict:
    """
    Run the full evaluation pipeline.

    Args:
        dataset_path: Path to the JSON dataset (default: config.EVAL_DATASET_PATH).
        model:        LLM model name (overrides config.LLM_MODEL if given).
        limit:        Max alerts to evaluate (default: all).
        verbose:      Print per-alert progress.
        save_results: Persist metrics JSON to eval/results/.

    Returns:
        Metrics dict from compute_all_metrics().
    """
    from agent.agent import SecurityAgent

    dataset_path = dataset_path or EVAL_DATASET_PATH
    model        = model or config.LLM_MODEL

    dataset = _load_dataset(Path(dataset_path))
    if limit:
        dataset = dataset[:limit]

    print(f"\n[*] Evaluating {len(dataset)} alerts with model={model}")

    agent        = SecurityAgent(model=model)
    results      = []
    ground_truth = []

    for i, item in enumerate(dataset, 1):
        raw_alert = item["alert"]
        gt        = item["ground_truth"]
        ground_truth.append(gt)

        if verbose:
            print(f"  [{i:3d}/{len(dataset)}] {raw_alert.get('alert_id')} "
                  f"(type={raw_alert.get('type')}, gt={gt})", end=" ... ", flush=True)

        result = agent.analyze(raw_alert)
        results.append(result)

        if verbose:
            pred = result.get("severity", "?")
            match = "[OK]" if pred == gt else "[X]"
            print(f"{match} predicted={pred}")

    metrics = compute_all_metrics(results, ground_truth)
    metrics["model"] = model
    metrics["evaluated_at"] = datetime.utcnow().isoformat() + "Z"
    metrics["alert_count"]  = len(results)

    if save_results:
        results_dir = Path(EVAL_RESULTS_DIR)
        results_dir.mkdir(parents=True, exist_ok=True)
        ts   = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        path = results_dir / f"metrics_{model.replace('-', '_')}_{ts}.json"
        with open(path, "w") as f:
            json.dump(metrics, f, indent=2)
        print(f"\n[SAVED] Metrics saved: {path}")

    return metrics


def main():
    parser = argparse.ArgumentParser(description="Run cybersecurity evaluation")
    parser.add_argument("--model",  default=None,
                        choices=["gpt-4o", "gpt-4o-mini"],
                        help="Override model (default: config.LLM_MODEL)")
    parser.add_argument("--limit",  type=int, default=None,
                        help="Max alerts to evaluate")
    parser.add_argument("--quiet",  action="store_true",
                        help="Suppress per-alert output")
    args = parser.parse_args()

    metrics = run_evaluation(
        model=args.model, limit=args.limit, verbose=not args.quiet
    )

    print("\n[RESULTS] EVALUATION SUMMARY")
    print("=" * 50)
    s = metrics.get("summary", {})
    print(f"  Total alerts:      {s.get('total_alerts')}")
    print(f"  Accuracy:          {s.get('accuracy', 0):.1%}")
    print(f"  Groundedness:      {s.get('groundedness_score', 0):.1%}")
    print(f"  Safety pass rate:  {s.get('safety_pass_rate', 0):.1%}")
    c = metrics.get("classification", {})
    print(f"  Precision:         {c.get('precision', 0):.3f}")
    print(f"  Recall:            {c.get('recall', 0):.3f}")
    print(f"  F1:                {c.get('f1', 0):.3f}")
    lat = metrics.get("latency", {})
    print(f"  Avg latency:       {lat.get('mean_ms', 0)}ms")
    cost = metrics.get("cost", {})
    print(f"  Cost/alert:        ${cost.get('cost_per_alert_usd', 0):.5f}")
    print(f"  Monthly @ 10K/day: ${cost.get('projected_monthly_usd', 0):,.2f}")


if __name__ == "__main__":
    main()
