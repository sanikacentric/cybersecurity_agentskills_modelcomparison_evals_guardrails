"""
eval/metrics.py — Evaluation metrics computation.

Computes:
  - Groundedness score (did the agent cite tool results?)
  - Classification metrics (precision, recall, F1 by severity)
  - Latency statistics (mean, p50, p95)
  - Cost projections (per-alert, daily @ 10K, monthly)
  - Safety pass rate (guardrail triggers)
"""

from __future__ import annotations
import statistics
from collections import defaultdict

from config import SEVERITY_LEVELS


def _groundedness_score(results: list[dict]) -> float:
    """
    Fraction of results that have at least one grounding source
    and at least one tool call.
    """
    if not results:
        return 0.0
    grounded = sum(
        1 for r in results
        if r.get("grounding_sources") and r.get("tool_calls_made")
    )
    return grounded / len(results)


def _classification_metrics(
    predictions: list[str], ground_truth: list[str]
) -> dict:
    """Precision, recall, F1 weighted across severity classes."""
    labels = SEVERITY_LEVELS + ["HUMAN_REVIEW"]
    tp = defaultdict(int)
    fp = defaultdict(int)
    fn = defaultdict(int)

    for pred, true in zip(predictions, ground_truth):
        if pred == true:
            tp[true] += 1
        else:
            fp[pred] += 1
            fn[true] += 1

    total = len(predictions)
    weighted_p = weighted_r = weighted_f1 = 0.0

    for label in labels:
        support  = ground_truth.count(label)
        if support == 0:
            continue
        weight = support / total
        p  = tp[label] / max(tp[label] + fp[label], 1)
        r  = tp[label] / max(tp[label] + fn[label], 1)
        f1 = 2 * p * r / max(p + r, 1e-9)
        weighted_p  += weight * p
        weighted_r  += weight * r
        weighted_f1 += weight * f1

    accuracy = sum(tp.values()) / max(total, 1)

    return {
        "accuracy":  round(accuracy, 4),
        "precision": round(weighted_p, 4),
        "recall":    round(weighted_r, 4),
        "f1":        round(weighted_f1, 4),
        "total":     total,
    }


def _latency_stats(results: list[dict]) -> dict:
    latencies = [r.get("latency_ms", 0) for r in results]
    if not latencies:
        return {}
    sorted_lat = sorted(latencies)
    n = len(sorted_lat)
    return {
        "mean_ms":   round(statistics.mean(latencies)),
        "median_ms": round(statistics.median(latencies)),
        "p95_ms":    round(sorted_lat[int(n * 0.95)]),
        "p99_ms":    round(sorted_lat[int(n * 0.99)]),
        "min_ms":    round(sorted_lat[0]),
        "max_ms":    round(sorted_lat[-1]),
    }


def _cost_stats(results: list[dict]) -> dict:
    costs  = [r.get("estimated_cost_usd", 0.0) for r in results]
    tokens = [r.get("tokens_used", 0) for r in results]
    if not costs:
        return {}
    avg_cost   = statistics.mean(costs) if costs else 0
    daily_10k  = avg_cost * 10_000
    monthly    = daily_10k * 30
    return {
        "avg_cost_usd":             round(avg_cost, 6),
        "cost_per_alert_usd":       round(avg_cost, 6),
        "avg_tokens_per_alert":     round(statistics.mean(tokens)) if tokens else 0,
        "projected_daily_10k_usd":  round(daily_10k, 2),
        "projected_monthly_usd":    round(monthly, 2),
        "total_cost_usd":           round(sum(costs), 4),
    }


def _safety_stats(results: list[dict]) -> dict:
    total    = len(results)
    triggers = sum(1 for r in results if r.get("guardrail_triggered"))
    return {
        "guardrail_triggers":    triggers,
        "safety_pass_rate":      round(1 - triggers / max(total, 1), 4),
        "human_review_routed":   sum(1 for r in results if r.get("severity") == "HUMAN_REVIEW"),
    }


def compute_all_metrics(results: list[dict], ground_truth: list[str]) -> dict:
    """
    Compute the full metrics suite for an evaluation run.

    Args:
        results:      List of agent verdict dicts.
        ground_truth: Parallel list of ground-truth severity strings.

    Returns:
        Nested metrics dict with summary, classification, latency, cost, safety.
    """
    predictions = [r.get("severity", "HUMAN_REVIEW") for r in results]

    classification = _classification_metrics(predictions, ground_truth)
    latency        = _latency_stats(results)
    cost           = _cost_stats(results)
    safety         = _safety_stats(results)
    groundedness   = _groundedness_score(results)

    return {
        "summary": {
            "total_alerts":       len(results),
            "groundedness_score": round(groundedness, 4),
            "safety_pass_rate":   safety["safety_pass_rate"],
            "accuracy":           classification["accuracy"],
        },
        "classification": classification,
        "latency":        latency,
        "cost":           cost,
        "safety":         safety,
    }
