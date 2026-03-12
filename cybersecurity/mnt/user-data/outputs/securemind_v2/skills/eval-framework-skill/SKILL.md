---
name: eval-framework-skill
description: Evaluate and benchmark SecureMind's AI security agent across quality metrics. Use this skill when measuring agent performance, comparing GPT-4o vs GPT-4o-mini, generating evaluation reports, checking groundedness scores, or running the full test dataset. Triggers on: evaluate, benchmark, metrics, precision, recall, F1, groundedness, model comparison, cost analysis, latency.
---

# Evaluation Framework Skill

This skill measures whether the SecureMind agent is actually reliable —
not just impressive-looking. It computes groundedness, precision/recall,
latency, cost, and safety metrics across 100 labeled test alerts.

## When to Use

- You want to know "how good is the agent actually?"
- Comparing GPT-4o vs GPT-4o-mini quality tradeoffs
- Checking if a code change improved or degraded performance
- Generating a metrics report for stakeholders
- Running the interactive evaluation dashboard

## Quick Start

### 1. Generate the test dataset (first time only)
```bash
python skills/eval-framework-skill/scripts/build_dataset.py
```

### 2. Run full evaluation (GPT-4o)
```bash
python -m eval.runner
```

### 3. Run evaluation with GPT-4o-mini
```bash
python skills/eval-framework-skill/scripts/run_eval_mini.py
```

### 4. Compare both models head-to-head
```bash
python skills/eval-framework-skill/scripts/model_comparison.py
```

### 5. Launch eval dashboard
```bash
streamlit run eval/dashboard.py
```

## Metrics Explained

### Groundedness Score
**What it measures:** % of agent responses that cite at least one source.

Why it matters for security: An agent that makes up threat claims is dangerous.
Every severity verdict must be traceable to a specific piece of evidence.

- Target: > 85%
- If below target: Check that RAG is returning results (run ingest_threat_intel.py)

### Precision & Recall

We treat HIGH + CRITICAL as the "positive" class (true threat):

| Metric | Formula | Security Meaning |
|--------|---------|-----------------|
| Precision | TP / (TP + FP) | Of predicted threats, how many are real? |
| Recall | TP / (TP + FN) | Of real threats, how many did we catch? |
| F1 | harmonic mean | Balance of both |

**Security priority: recall > precision.** Missing a real attack is worse than a false alarm.

- Recall target: > 0.90
- Precision target: > 0.80

### Latency

| Percentile | Target |
|-----------|--------|
| P50 (median) | < 3,000ms |
| P90 | < 6,000ms |
| P95 | < 10,000ms |

### Cost per Alert

| Model | Target Cost |
|-------|------------|
| GPT-4o | < $0.005 |
| GPT-4o-mini | < $0.001 |

At 10,000 alerts/day:
- GPT-4o: ~$50/day, ~$1,500/month
- GPT-4o-mini: ~$10/day, ~$300/month

### Safety Pass Rate

% of adversarial inputs (prompt injection in alert fields) that were correctly
blocked by guardrails and routed to HUMAN_REVIEW.

Target: > 95%

## Dataset Composition

The 100-alert test set is balanced across attack types:

| Category | Count | Expected Severity |
|----------|-------|------------------|
| True positive logins | 30 | HIGH |
| False positive logins | 15 | LOW |
| Brute force | 15 | HIGH |
| Critical malware | 10 | CRITICAL |
| Unknown malware | 10 | MEDIUM |
| Privilege escalation | 10 | HIGH |
| Data exfiltration | 5 | CRITICAL |
| Adversarial injection | 5 | HUMAN_REVIEW |

## Reading the Confusion Matrix

The dashboard shows a severity confusion matrix. Key things to watch:
- **HIGH predicted as LOW** = dangerous false negative — fix immediately
- **LOW predicted as HIGH** = false positive — acceptable but reduces analyst trust
- **Any predicted as HUMAN_REVIEW** = low-confidence escalation — acceptable safety behavior

## Model Comparison Output

```
╔══════════════════════════════════════════════════════════╗
║           GPT-4o vs GPT-4o-mini Comparison               ║
╠══════════════════════════════════════════════════════════╣
║ Metric              GPT-4o        GPT-4o-mini             ║
║ Groundedness        91%           84%                     ║
║ Precision           0.89          0.82                    ║
║ Recall              0.94          0.88                    ║
║ F1                  0.91          0.85                    ║
║ Avg Latency         2,400ms       890ms                   ║
║ Cost/alert          $0.0032       $0.0008                 ║
║ Safety pass rate    98%           95%                     ║
║ Monthly (10K/day)   $960          $240                    ║
╚══════════════════════════════════════════════════════════╝
Recommendation: Use gpt-4o-mini for LOW/MEDIUM alerts (75% of volume)
                Use gpt-4o for HIGH/CRITICAL alerts (25% of volume)
                Estimated blended monthly cost: $390 (vs $960 all-4o)
```

## Continuous Eval Strategy

For production: run evaluations on every code change (CI/CD):
```bash
python -m eval.runner --limit 20   # Quick smoke test (20 alerts)
python -m eval.runner              # Full eval before releases
```

If recall drops below 0.85, block the deployment.
