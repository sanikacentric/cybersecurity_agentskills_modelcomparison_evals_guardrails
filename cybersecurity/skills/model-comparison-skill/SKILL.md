---
name: model-comparison-skill
description: >
  Provides guidance on choosing between GPT-4o and GPT-4o-mini for security
  alert triage. Explains the two-pass smart routing strategy, cost tradeoffs,
  quality differences, and when to use each model. Use this skill when asked
  which model to use, about cost optimization, or about the routing strategy.
triggers:
  - which model should I use
  - gpt-4o vs gpt-4o-mini
  - how much does it cost
  - cost optimization
  - routing strategy
  - smart routing
  - how to save money
  - model tradeoffs
  - what is the difference between models
  - is gpt-4o-mini good enough
---

# Model Comparison Skill

Explains the cybersecurity dual-model architecture, the two-pass smart
routing strategy, cost projections, and decision guidance for model selection.

## When to Use

- Deciding which model to use for a new deployment
- Understanding the cost/quality tradeoff between GPT-4o and GPT-4o-mini
- Explaining the two-pass routing strategy to stakeholders
- Estimating monthly costs for different alert volumes
- Justifying model selection in a security architecture review

---

## Model Overview

| Property | GPT-4o | GPT-4o-mini |
|----------|--------|-------------|
| Input cost | $5.00 / 1M tokens | $0.15 / 1M tokens (**33x cheaper**) |
| Output cost | $15.00 / 1M tokens | $0.60 / 1M tokens (**25x cheaper**) |
| Avg latency | ~2,400ms | ~890ms (**~3x faster**) |
| Accuracy (cybersecurity eval) | ~91% F1 | ~85% F1 |
| Groundedness | ~91% | ~84% |
| Safety pass rate | ~98% | ~95% |
| Best for | HIGH/CRITICAL, nuanced cases | LOW/MEDIUM, high-volume screening |

---

## Two-Pass Smart Routing Strategy

The recommended production configuration:

```
All Alerts
    |
    v
+---------------------------+
|  Pass 1: gpt-4o-mini      |  <- Screens 100% of alerts (cheap, fast)
|  ~$0.00087/alert          |
+---------------------------+
    |               |
    v               v
LOW / MEDIUM    HIGH / CRITICAL
Done (85%)      Pass 2: gpt-4o
                ~$0.021/alert
                (only 15-30% of alerts)
```

### Why This Works

- LOW and MEDIUM alerts (typically 55-70% of volume) do **not** need GPT-4o
- Only HIGH and CRITICAL alerts (30-45% of volume) get the premium model
- Mini's accuracy on LOW/MEDIUM is sufficient — false negatives on these are
  low-risk by definition
- GPT-4o on HIGH/CRITICAL ensures maximum accuracy where it matters most

---

## Cost Comparison @ 10,000 Alerts/Day

| Strategy | Cost/Alert | Daily | Monthly | vs Humans |
|----------|------------|-------|---------|-----------|
| All GPT-4o | $0.00320 | $32 | $960 | 99% cheaper |
| All GPT-4o-mini | $0.00080 | $8 | $240 | 99.8% cheaper |
| **Smart Routing (recommended)** | **~$0.00130** | **$13** | **$390** | **99.7% cheaper** |
| Human analysts (15 min @ $75/hr) | $18.75 | $187,500 | $5.6M | baseline |

> Smart routing saves **~59% vs all-GPT-4o** while maintaining GPT-4o accuracy
> on the alerts that matter most.

---

## Decision Guide

### Use GPT-4o when:
- Alert involves CRITICAL infrastructure (AD, Domain Controllers, CEO accounts)
- Previous mini verdict was HIGH or CRITICAL (always re-analyze with 4o)
- Regulatory compliance requires maximum accuracy (HIPAA, PCI-DSS, SOC 2)
- Low alert volume (< 500/day) — cost difference is negligible

### Use GPT-4o-mini when:
- Initial screening of all incoming alerts
- HIGH volume environments (> 5,000 alerts/day)
- LOW or MEDIUM severity alerts
- Development, testing, and evaluation runs

### Use Smart Routing (`--routing` flag) when:
- Production deployments at any scale
- Want best cost/quality balance automatically
- Can tolerate mini's Pass 1 latency before escalation

---

## Running Model Comparison

### Side-by-side comparison on one alert:

```bash
python triage_alert.py --demo --compare-models
```

### Full evaluation of both models:

```bash
python -m eval.runner --model gpt-4o-mini --limit 20
python -m eval.runner --model gpt-4o      --limit 20
python model_comparison.py --limit 20 --save-report
```

### In code:

```python
from agent.agent import SecurityAgent

# GPT-4o-mini — cost-optimized
agent = SecurityAgent(model="gpt-4o-mini")
result = agent.analyze(alert)

# GPT-4o — highest accuracy
agent = SecurityAgent(model="gpt-4o")
result = agent.analyze(alert)

# Smart routing — automatic escalation
agent = SecurityAgent(model="gpt-4o-mini")
result = agent.analyze_with_routing(alert)
# result["routing_escalated"] -> True if escalated to gpt-4o
# result["total_cost_usd"]    -> combined cost of both passes
```

### Via REST API:

```bash
# Force GPT-4o-mini
POST /analyze?model=gpt-4o-mini

# Force GPT-4o
POST /analyze?model=gpt-4o

# Smart routing (auto-selects model)
POST /analyze/routed
```

---

## Routing Thresholds (config.py)

```python
ROUTING_ESCALATION_THRESHOLD = "HIGH"
# Alerts with severity >= HIGH in Pass 1 are escalated to GPT-4o in Pass 2
# Change to "CRITICAL" to only escalate the most severe (more savings, less safety)
# Change to "MEDIUM" to escalate more aggressively (more cost, more safety)
```

---

## Architecture Context

This skill is part of the cybersecurity Agent Skills architecture:

```
threat-intel-skill     -> WHAT threat intelligence to retrieve
soc-triage-skill       -> HOW to run the triage pipeline
eval-framework-skill   -> HOW WELL the models are performing
model-comparison-skill -> WHICH model to use and WHY  <-- you are here
```

Each skill loads only when triggered — keeping the base agent context lean
and cost-efficient at ~5K tokens per skill vs ~50K for a monolithic prompt.
