---
name: model-comparison-skill
description: Compare GPT-4o vs GPT-4o-mini performance for security alert triage. Use this skill when deciding which model to use, understanding cost-quality tradeoffs, implementing model routing strategies, or justifying model selection decisions. Triggers on: model comparison, gpt-4o-mini, cost optimization, model routing, which model, cheaper model, faster model.
---

# Model Comparison Skill

This skill answers the critical engineering question:
**"Should I use GPT-4o or GPT-4o-mini for security triage?"**

The answer: it depends on severity. This skill helps you implement
a smart routing strategy that saves ~60% on LLM costs.

## The Core Insight

Not all alerts need the same model:

| Severity | % of volume | Recommended Model | Reason |
|----------|------------|------------------|--------|
| CRITICAL | ~5% | GPT-4o | Accuracy is life-or-death |
| HIGH | ~20% | GPT-4o | Need high recall, can't miss threats |
| MEDIUM | ~35% | GPT-4o-mini | Good enough, 10x cheaper |
| LOW | ~40% | GPT-4o-mini | False positives acceptable |

**Blended cost at 10K alerts/day:**
- All GPT-4o: ~$1,500/month
- All GPT-4o-mini: ~$300/month
- Smart routing (25% 4o / 75% mini): ~$525/month → **65% savings**

## Quick Commands

### Single alert comparison
```bash
python skills/soc-triage-skill/scripts/triage_alert.py --demo --compare-models
```

### Full dataset comparison (both models, 100 alerts each)
```bash
python skills/eval-framework-skill/scripts/model_comparison.py
```

### Quick 20-alert comparison
```bash
python skills/eval-framework-skill/scripts/model_comparison.py --limit 20
```

## Model Specs

| Property | GPT-4o | GPT-4o-mini |
|----------|--------|-------------|
| Input cost | $5.00/1M tokens | $0.15/1M tokens |
| Output cost | $15.00/1M tokens | $0.60/1M tokens |
| Context window | 128K tokens | 128K tokens |
| Typical latency | 2–4 seconds | 0.5–1.5 seconds |
| Best for | Critical decisions | High-volume screening |

## Model Routing Strategy

The recommended implementation: **two-pass triage**

```
Pass 1 (gpt-4o-mini, fast):
  → Run all alerts through mini
  → Any result with severity HIGH or CRITICAL:
      → Escalate to Pass 2

Pass 2 (gpt-4o, accurate):
  → Re-analyze escalated alerts
  → Final verdict from GPT-4o
  → All others: accept mini result
```

This gives GPT-4o accuracy where it matters and GPT-4o-mini speed/cost where it doesn't.

## Configuring the Model

Change the model in `config.py`:
```python
LLM_MODEL = "gpt-4o"        # Default: highest accuracy
LLM_MODEL = "gpt-4o-mini"   # Cost-optimized: 33x cheaper input tokens
```

Or pass `--model` flag to triage scripts:
```bash
python skills/soc-triage-skill/scripts/triage_alert.py --demo --model gpt-4o-mini
```

## When GPT-4o-mini Falls Short

Based on typical eval results, mini is weaker at:
1. **Nuanced edge cases** — alerts that are 50/50 between severity levels
2. **Multi-indicator reasoning** — alerts requiring combining 3+ signals
3. **Adversarial inputs** — more susceptible to prompt injection attempts

Mitigation: Use guardrails (confidence gating) — if mini scores < 65% confidence,
automatically escalate to GPT-4o for re-analysis.

## Reading Comparison Results

When you run model_comparison.py, look for:

- **Recall difference > 0.05**: Mini is missing real threats → use GPT-4o for HIGH+
- **Cost savings > 50%**: Mini is significantly cheaper for your workload
- **Latency difference > 2x**: Mini is much faster (good for real-time pipelines)
- **Safety pass rate difference**: If mini scores below 90%, add extra guardrails
