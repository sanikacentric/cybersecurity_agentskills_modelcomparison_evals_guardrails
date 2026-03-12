---
name: eval-framework-skill
description: >
  Run rigorous evaluation of cybersecurity's triage quality, measuring
  groundedness, precision, recall, F1, latency percentiles, cost per alert,
  and safety pass rate. Supports both GPT-4o and GPT-4o-mini evaluation.
  Use this skill when asked to evaluate model quality, run benchmarks, measure
  accuracy, compare metrics, or assess performance.
triggers:
  - evaluate the model
  - run evaluation
  - measure accuracy
  - benchmark
  - what is the F1 score
  - how accurate is it
  - run metrics
  - how well does it perform
  - quality assessment
---

# Evaluation Framework Skill

Runs the full cybersecurity evaluation pipeline against a synthetic labeled
dataset of 100 security alerts, computing groundedness, classification metrics,
latency percentiles, cost projections, and safety pass rate.

## When to Use

- Measuring triage quality after updating threat intel or model
- Comparing GPT-4o vs GPT-4o-mini quality/cost tradeoff
- Generating metrics for stakeholder reporting
- Validating model performance before production deployment
- Investigating accuracy regressions

## Scripts in This Skill

| Script | Purpose |
|--------|---------|
| `scripts/model_comparison.py` | Full GPT-4o vs GPT-4o-mini side-by-side evaluation with printed comparison table |

---

## Usage

### Step 1 — Build the evaluation dataset (run once)

```bash
python -m eval.dataset_builder
# Creates: data/synthetic_alerts/test_dataset.json (100 labeled alerts)

python -m eval.dataset_builder --count 200
# Custom size
```

### Step 2 — Run evaluation for a specific model

```bash
# GPT-4o-mini (recommended first — cheapest)
python -m eval.runner --model gpt-4o-mini

# GPT-4o (for quality baseline)
python -m eval.runner --model gpt-4o

# Limit to N alerts (faster for testing)
python -m eval.runner --model gpt-4o-mini --limit 20

# Suppress per-alert output
python -m eval.runner --model gpt-4o-mini --quiet
```

### Step 3 — Run full side-by-side comparison

```bash
python skills/eval-framework-skill/scripts/model_comparison.py
python skills/eval-framework-skill/scripts/model_comparison.py --limit 20
python skills/eval-framework-skill/scripts/model_comparison.py --save-report
```

### Step 4 — View results in the dashboard

```bash
streamlit run eval/dashboard.py
# Open: http://localhost:8501 -> Model Comparison tab
```

---

## Metrics Explained

### Groundedness Score

Fraction of verdicts that cite at least one tool call result in their grounding
sources. A well-grounded verdict means the agent used evidence, not hallucination.

```
groundedness = alerts_with_tool_evidence / total_alerts
Target: > 0.85
```

### Classification Metrics (Precision / Recall / F1)

Weighted across all severity classes (LOW, MEDIUM, HIGH, CRITICAL).

| Metric | What It Measures |
|--------|-----------------|
| Precision | Of all HIGH predictions, how many were actually HIGH? |
| Recall | Of all actual HIGH alerts, how many did we catch as HIGH? |
| F1 | Harmonic mean of precision and recall |
| Accuracy | Overall fraction of exactly-correct severity predictions |

> In security, **recall is more important than precision** — missing a real attack
> (false negative) is far more costly than a false positive.

### Latency Percentiles

| Metric | Definition |
|--------|-----------|
| Mean | Average response time across all alerts |
| P50 (Median) | 50% of alerts complete within this time |
| P95 | 95% of alerts complete within this time — use for SLA planning |
| P99 | Worst-case latency for 99% of alerts |

### Cost Projections

```
cost_per_alert    = (input_tokens * price_in) + (output_tokens * price_out)
daily_10k_cost    = cost_per_alert * 10,000
monthly_cost      = daily_10k_cost * 30
```

### Safety Pass Rate

```
safety_pass_rate  = 1 - (guardrail_triggers / total_alerts)
Target: > 0.95
```

---

## Output Format

Metrics are saved as JSON to `eval/results/metrics_<model>_<timestamp>.json`:

```json
{
  "model": "gpt-4o-mini",
  "evaluated_at": "2024-01-15T12:00:00Z",
  "alert_count": 100,
  "summary": {
    "total_alerts": 100,
    "groundedness_score": 0.91,
    "safety_pass_rate": 0.97,
    "accuracy": 0.72
  },
  "classification": {
    "accuracy": 0.72,
    "precision": 0.74,
    "recall": 0.72,
    "f1": 0.71,
    "total": 100
  },
  "latency": {
    "mean_ms": 1820,
    "median_ms": 1650,
    "p95_ms": 3200,
    "p99_ms": 4100,
    "min_ms": 890,
    "max_ms": 5600
  },
  "cost": {
    "cost_per_alert_usd": 0.00087,
    "avg_tokens_per_alert": 1230,
    "projected_daily_10k_usd": 8.70,
    "projected_monthly_usd": 261.00,
    "total_cost_usd": 0.087
  },
  "safety": {
    "guardrail_triggers": 3,
    "safety_pass_rate": 0.97,
    "human_review_routed": 5
  }
}
```

---

## Comparison Table Output

Running `model_comparison.py` prints:

```
╔══════════════════════════════════════════════════════════╗
║    GPT-4o vs GPT-4o-mini — cybersecurity Evaluation  ║
╠══════════════════════════════════════════════════════════╣
║  Metric                   GPT-4o      GPT-4o-mini        ║
╠══════════════════════════════════════════════════════════╣
║  QUALITY METRICS                                         ║
║  Groundedness             91%         84%                ║
║  Precision                0.890       0.820              ║
║  Recall                   0.940       0.880              ║
║  F1 Score                 0.910       0.850              ║
║  Safety Pass Rate         98%         95%                ║
║  PERFORMANCE                                             ║
║  Avg Latency              2400ms      890ms              ║
║  P95 Latency              4100ms      1600ms             ║
║  COST                                                    ║
║  Cost per alert           $0.00320    $0.00080           ║
║  Monthly @ 10K/day        $960        $240               ║
╚══════════════════════════════════════════════════════════╝
💡 Monthly savings with smart routing: ~$570 (59% cheaper)
```

---

## Evaluation Dataset

The dataset (`data/synthetic_alerts/test_dataset.json`) contains 100 labeled alerts:

| Severity | Count | Alert Types |
|----------|-------|-------------|
| CRITICAL | ~15 | WannaCry, APT C2, admin impossible travel |
| HIGH | ~30 | Cobalt Strike, privilege escalation, data exfiltration |
| MEDIUM | ~25 | Cross-region login, network anomaly |
| LOW | ~30 | Same-city login, benign PUP, minor anomaly |
