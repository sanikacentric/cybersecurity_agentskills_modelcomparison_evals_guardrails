# cybersecurity — AI-Native Security Operations Platform

> **An autonomous SOC analyst powered by GPT-4o + GPT-4o-mini, RAG over real threat intelligence,
> Anthropic Agent Skills architecture, and a rigorous self-evaluation framework.**

---

## Table of Contents

1. [Project Goal](#1-project-goal)
2. [The Problem](#2-the-problem)
3. [The Solution](#3-the-solution)
4. [What Makes This Unique](#4-what-makes-this-unique)
5. [How Agent Skills Help](#5-how-agent-skills-help)
6. [System Architecture](#6-system-architecture)
7. [File-by-File Reference](#7-file-by-file-reference)
8. [Quick Start — Python Commands](#8-quick-start--python-commands)
9. [Run Everything (One Command)](#9-run-everything-one-command)
10. [Tech Stack](#10-tech-stack)

---

## 1. Project Goal

**cybersecurity** automates the first line of defense in a Security Operations Center (SOC).

The goal is to replace the slow, expensive, and error-prone manual triage process — where human
analysts read raw security alerts and decide what to do — with an AI agent that:

- **Ingests** raw alerts from platforms like Microsoft Sentinel
- **Retrieves** relevant threat intelligence via vector search (MITRE ATT&CK, CVEs, malicious IPs)
- **Reasons** through evidence using multi-step tool calls
- **Outputs** a structured verdict: severity + confidence + explanation + recommended actions
- **Routes** automatically to SOAR, or escalates to a human analyst
- **Evaluates itself** — measuring accuracy, groundedness, latency, and cost per alert

This is a production-grade demonstration of what **Microsoft Security Copilot** does internally,
built with open-source tools and two OpenAI models.

---

## 2. The Problem

Modern enterprise Security Operations Centers face a **data-volume crisis**:

| Metric | Reality |
|--------|---------|
| Avg alerts per day (large enterprise) | 10,000 – 150,000 |
| Avg analyst triage time per alert | 10 – 30 minutes |
| % of alerts that are false positives | 45 – 70% |
| Mean time to detect a real breach | **197 days** |
| SOC analyst annual cost (USA) | $85,000 – $130,000 |
| Analyst burnout rate | 70%+ report alert fatigue |

**The consequences:**

- Real attacks hide inside thousands of low-quality alerts
- Analysts waste hours on false positives
- Critical HIGH/CRITICAL alerts sit in a queue for hours — sometimes days
- One missed alert can become a $4.5M breach (IBM Cost of Data Breach 2023)

**Existing tools fall short:**

- **Rule-based SIEM** — rigid, no context, floods analysts with noise
- **Manual playbooks** — cannot scale to alert volume
- **Basic ML classifiers** — no reasoning, no explainability, no threat intel integration
- **Human-only SOC** — slow, expensive, does not scale at 3 AM

---

## 3. The Solution

cybersecurity is a **multi-tool AI agent** that thinks like a senior SOC analyst:

```
Raw Alert
    |
    v
+----------------------------------------------------------+
|                  cybersecurity Agent                 |
|                                                          |
|  1. Parse & validate alert (Pydantic)                    |
|  2. Prompt injection scan (guardrails)                   |
|  3. LLM reasons -> calls tools:                          |
|     +- check_impossible_travel   (physics-based)         |
|     +- check_login_history       (user baseline)         |
|     +- lookup_file_hash          (malware DB)            |
|     +- search_threat_intel       (ChromaDB RAG)          |
|  4. LLM synthesizes evidence -> JSON verdict             |
|  5. Post-flight guardrails (confidence gate)             |
|  6. SOAR router -> AUTO_RESPOND or HUMAN_REVIEW          |
+----------------------------------------------------------+
    |
    v
{
  "severity": "CRITICAL",
  "confidence": 0.92,
  "explanation": "Login from Romania 2h after New York login —
                  impossible travel confirmed (9,234 km at 4,617 kph).
                  Source IP 185.220.101.45 is a known Tor exit node.",
  "recommended_actions": ["Reset password", "Enable MFA", "Block IP"],
  "mitre_techniques": ["T1078", "T1090"],
  "soar_action": "AUTO_RESPOND"
}
```

### Two-Pass Routing Strategy

cybersecurity implements a smart cost-optimization strategy — not all alerts need the
most expensive model:

```
All Alerts
    |
    v
gpt-4o-mini  (Pass 1 — screens everything)
    |
    +-- LOW / MEDIUM  -----------------------> Done   ($0.00087/alert)
    |
    +-- HIGH / CRITICAL ---------------------> gpt-4o (Pass 2)
                                                    |
                                                    v
                                              Final verdict ($0.021/alert)
```

| Strategy | Monthly Cost @ 10K alerts/day |
|----------|-------------------------------|
| All GPT-4o | ~$6,200 |
| All GPT-4o-mini | ~$260 |
| **cybersecurity Smart Routing** | **~$390** |
| Human analysts (15 min/alert @ $75/hr) | ~$112,500 |

**cybersecurity saves 96% vs human analysts and 94% vs all-GPT-4o.**

---

## 4. What Makes This Unique

### 4.1 Evidence-Grounded Verdicts
Unlike rule-based SIEMs or simple classifiers, every cybersecurity verdict is backed by
**tool call evidence**. The agent is required by prompt to never speculate — if it cannot
find evidence, it routes to HUMAN_REVIEW. This makes every decision **auditable**.

### 4.2 Physics-Based Impossible Travel Detection
The `check_impossible_travel` tool uses the **Haversine formula** to compute great-circle
distances between login locations and checks whether the required travel speed exceeds
1,000 km/h (max commercial flight speed). This is a deterministic check — no hallucination
possible — combined with LLM reasoning for context.

### 4.3 Real Threat Intelligence via RAG
The agent does not rely on training-time knowledge. It performs **live vector search** over
a ChromaDB database containing:
- MITRE ATT&CK technique descriptions
- Known malicious IP ranges (Tor exit nodes, APT C2 infrastructure)
- CVE intelligence with CVSS scores and mitigations

This means the threat intel database can be updated **without retraining the model**.

### 4.4 Prompt Injection Protection
Security agents are high-value targets for adversarial inputs. cybersecurity scans
every alert for injection patterns (`ignore previous instructions`, `jailbreak`, etc.)
**before** it is sent to the LLM. Poisoned alerts are quarantined automatically.

### 4.5 Self-Evaluating System
The built-in evaluation framework measures:
- **Groundedness** — did the agent use tool evidence in its verdict?
- **Classification metrics** — precision, recall, F1 per severity class
- **Cost per alert** — real token usage tracked per call
- **Latency percentiles** — mean, median, P95, P99
- **Safety pass rate** — how often guardrails fire correctly

This creates a **feedback loop**: measure model quality degradation over time and
trigger model upgrades automatically.

### 4.6 Dual-Model Architecture with Live Routing
Most AI security tools are single-model. cybersecurity dynamically **selects the model
at runtime** based on initial severity screening — a pattern used by enterprise AI products
at scale.

---

## 5. How Agent Skills Help

cybersecurity is built on the **Anthropic Agent Skills architecture** — capabilities
packaged as self-describing, on-demand skill modules. Each skill lives under `skills/`
and has:

- A `SKILL.md` file with YAML frontmatter (`name`, `description`, `triggers`)
- Optional `scripts/` directory with directly executable tools
- **Loads only when triggered** (~5K tokens), not always in context

### Skills Directory Structure

```
skills/
├── threat-intel-skill/
│   ├── SKILL.md                  <- triggers: "IP lookup", "MITRE", "hash check", "CVE"
│   └── scripts/
│       ├── search_intel.py       <- semantic vector search over ChromaDB
│       └── hash_lookup.py        <- malware signature DB lookup
│
├── soc-triage-skill/
│   ├── SKILL.md                  <- triggers: "analyze alert", "triage", "SOC", "severity"
│   └── scripts/
│       └── triage_alert.py       <- full triage: --demo, --model, --compare-models
│
├── eval-framework-skill/
│   ├── SKILL.md                  <- triggers: "evaluate", "metrics", "benchmark", "F1"
│   └── scripts/
│       └── model_comparison.py   <- GPT-4o vs mini side-by-side evaluation + report
│
└── model-comparison-skill/
    └── SKILL.md                  <- triggers: "which model", "cost", "routing", "savings"
                                     (guidance-only skill — no scripts needed)
```

### Skills Inventory

| Skill | SKILL.md Triggers | Scripts | What It Provides |
|-------|-------------------|---------|-----------------|
| `threat-intel-skill` | "IP lookup", "MITRE", "hash check", "CVE query" | `search_intel.py`, `hash_lookup.py` | Live vector search + malware hash DB |
| `soc-triage-skill` | "analyze alert", "triage", "SOC", "is this a threat" | `triage_alert.py` | Full triage pipeline with model selection |
| `eval-framework-skill` | "evaluate", "metrics", "benchmark", "how accurate" | `model_comparison.py` | Full model evaluation + comparison report |
| `model-comparison-skill` | "which model", "cost", "routing", "savings" | _(none)_ | Routing strategy + pricing guidance |

### SKILL.md Format

Each `SKILL.md` follows the Anthropic Agent Skills spec:

```yaml
---
name: soc-triage-skill
description: >
  Analyze and triage security alerts using cybersecurity's AI-powered SOC agent.
  Supports GPT-4o (highest accuracy) and GPT-4o-mini (cost-optimized).
triggers:
  - analyze alert
  - triage this alert
  - what severity is this
  - SOC analysis
---

# SOC Triage Skill
... (usage docs, output format, examples) ...
```

The YAML frontmatter is machine-readable — an orchestrator can scan all `SKILL.md`
files, match `triggers` against user intent, and load only the relevant skill body.

### Why This Architecture Matters

```
Without Agent Skills                  With Agent Skills
-----------------------------         ------------------------------
Full system prompt always loaded      Only relevant skill loads
~50K tokens per request               ~5K tokens per request
High cost, slow, context bloat        10x cheaper, focused, composable
One giant prompt is hard to maintain  Each skill is independently versioned
```

Agent Skills enable **progressive disclosure**: the agent starts lean and loads
specialized capabilities only when the task requires them. Each skill is also
**independently testable and deployable**.

### Tool Call Flow (inside the agent)

```python
# For suspicious_login — agent calls:
check_impossible_travel(current="Romania", prev="New York", gap=2.0)
check_login_history(user="john.doe@company.com")

# For malware_detected — agent calls:
lookup_file_hash("5f4dcc3b5aa765d61d8327deb882cf99")
search_threat_intel("WannaCry EternalBlue ransomware")

# For any alert type — agent may also call:
search_threat_intel("T1078 credential access Tor exit node")
```

Each tool returns structured JSON evidence. The LLM synthesizes across all tool
results to produce a grounded final verdict.

---

## 6. System Architecture

```
+-------------------------------------------------------------------------+
|                        cybersecurity System                         |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  |                  Anthropic Agent Skills Layer                     |  |
|  |                                                                   |  |
|  |  skills/threat-intel-skill/    skills/soc-triage-skill/          |  |
|  |  +-- SKILL.md (triggers)       +-- SKILL.md (triggers)           |  |
|  |  +-- scripts/search_intel.py   +-- scripts/triage_alert.py       |  |
|  |  +-- scripts/hash_lookup.py                                       |  |
|  |                                                                   |  |
|  |  skills/eval-framework-skill/  skills/model-comparison-skill/    |  |
|  |  +-- SKILL.md (triggers)       +-- SKILL.md (triggers+guidance)  |  |
|  |  +-- scripts/model_comparison.py                                  |  |
|  +--------------------------------+----------------------------------+  |
|                                   | invokes                            |
|  +--------------------------------v----------------------------------+  |
|  |                  cybersecurity Core Agent                     |  |
|  |                                                                   |  |
|  |  Raw Alert -> Parser -> Injection Check -> OpenAI Tool Loop       |  |
|  |                                                 |                 |  |
|  |        +----------------------------------------+                 |  |
|  |        | Tool Calls (1-4 per alert)              |                 |  |
|  |        v            v              v             v                |  |
|  |  search_threat  check_login  check_impossible  lookup_file        |  |
|  |  _intel()       _history()   _travel()         _hash()            |  |
|  |        |            |              |             |                |  |
|  |        +------------+--------------+-------------+                |  |
|  |                          | Evidence                               |  |
|  |                          v                                        |  |
|  |                 LLM Synthesizes Verdict (JSON)                    |  |
|  |                          |                                        |  |
|  |               Guardrails (confidence gate)                        |  |
|  |                          |                                        |  |
|  |                    SOAR Router                                    |  |
|  |            AUTO_RESPOND / LOG / HUMAN_REVIEW                      |  |
|  +-------------------------------------------------------------------+  |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  |               Two-Pass Smart Routing Layer                        |  |
|  |                                                                   |  |
|  |  Alert -> gpt-4o-mini (Pass 1) -> LOW/MEDIUM: Done ($0.00087)    |  |
|  |                        |                                          |  |
|  |                        +-> HIGH/CRITICAL -> gpt-4o ($0.021)       |  |
|  +-------------------------------------------------------------------+  |
|                                                                         |
|  +--------------+  +--------------+  +------------------------------+  |
|  |  FastAPI     |  |  Streamlit   |  |  Evaluation Framework        |  |
|  |  REST API    |  |  Dashboard   |  |                              |  |
|  |  /analyze    |  |  Overview    |  |  dataset_builder.py          |  |
|  |  /analyze/   |  |  Model Cmp   |  |  runner.py                   |  |
|  |  routed      |  |  Cost ROI    |  |  metrics.py                  |  |
|  |  /batch      |  |  Live Demo   |  |  dashboard.py                |  |
|  +--------------+  +--------------+  +------------------------------+  |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  |                     Data & Storage Layer                          |  |
|  |                                                                   |  |
|  |  ChromaDB (.chromadb/)          data/threat_intel/               |  |
|  |  OpenAI text-embedding-3-small  +-- mitre_attack.txt             |  |
|  |  Persistent vector store        +-- malicious_ips.txt            |  |
|  |                                 +-- cves.txt                     |  |
|  +-------------------------------------------------------------------+  |
+-------------------------------------------------------------------------+
```

### Alert Lifecycle (Step by Step)

```
Step 1  Alert arrives as JSON (via API POST or CLI --demo)
Step 2  agent/parser.py validates fields -> AlertModel (Pydantic)
Step 3  agent/guardrails.py scans for prompt injection keywords
Step 4  agent/agent.py sends alert + TOOLS_SCHEMA to OpenAI
Step 5  GPT model calls 1-4 tools with structured arguments
Step 6  Each tool returns JSON evidence (travel check, IP rep, hash, intel)
Step 7  GPT synthesizes all evidence -> final JSON verdict
Step 8  agent/guardrails.py: confidence gate, severity validation
Step 9  agent/router.py: assigns SOAR action + SLA
Step 10 Structured verdict returned to caller
```

---

## 7. File-by-File Reference

### Root Level

| File | Purpose |
|------|---------|
| `config.py` | Single source of truth — model names, pricing, paths, RAG params, routing thresholds, safety keywords |
| `main.py` | FastAPI REST API — `POST /analyze`, `/analyze/batch`, `/analyze/routed`, `GET /health`, `/metrics`, `/models` |
| `agent.py` | CLI entry point — re-exports from `agent/agent.py`; run with `--demo`, `--model`, `--routing` |
| `triage_alert.py` | Root-level alias for `skills/soc-triage-skill/scripts/triage_alert.py` — `--demo`, `--model`, `--compare-models` |
| `hash_lookup.py` | Root-level alias for `skills/threat-intel-skill/scripts/hash_lookup.py` — malware hash DB lookup |
| `search_intel.py` | Root-level alias for `skills/threat-intel-skill/scripts/search_intel.py` — ChromaDB semantic search |
| `model_comparison.py` | Root-level alias for `skills/eval-framework-skill/scripts/model_comparison.py` — full model eval |
| `SKILL.md` | Legacy root skill descriptor — superseded by `skills/threat-intel-skill/SKILL.md` |
| `requirements.txt` | All Python dependencies |
| `run.bat` | Windows batch — runs the entire project end-to-end with one double-click |

---

### `skills/` — Anthropic Agent Skills

| File | Purpose |
|------|---------|
| `skills/threat-intel-skill/SKILL.md` | Skill descriptor: triggers (`IP lookup`, `hash check`, `MITRE`, `CVE`), usage docs, output format for search and hash tools |
| `skills/threat-intel-skill/scripts/search_intel.py` | Semantic search over ChromaDB — `--top-k N`, `--format json\|text` |
| `skills/threat-intel-skill/scripts/hash_lookup.py` | Malware hash lookup — Mimikatz, WannaCry, Cobalt Strike, Adware |
| `skills/soc-triage-skill/SKILL.md` | Skill descriptor: triggers (`analyze alert`, `triage`, `SOC`), alert JSON format, severity definitions, tool call behavior by alert type |
| `skills/soc-triage-skill/scripts/triage_alert.py` | Full triage pipeline — `--demo`, `--model gpt-4o-mini`, `--compare-models` side-by-side |
| `skills/eval-framework-skill/SKILL.md` | Skill descriptor: triggers (`evaluate`, `metrics`, `benchmark`), metrics explained (groundedness, F1, latency, cost), full output format |
| `skills/eval-framework-skill/scripts/model_comparison.py` | GPT-4o vs GPT-4o-mini side-by-side evaluation — `--limit N`, `--save-report` |
| `skills/model-comparison-skill/SKILL.md` | Guidance-only skill (no scripts): triggers (`which model`, `cost`, `routing`), model pricing table, routing thresholds, decision guide, cost projections |

---

### `agent/` Package — Core AI Agent

| File | Purpose |
|------|---------|
| `agent/agent.py` | **Main orchestrator.** `SecurityAgent` class with `analyze()` and `analyze_with_routing()`. Implements the OpenAI tool-calling agentic loop — sends alert, dispatches tool calls in a loop until final JSON verdict. |
| `agent/parser.py` | **Alert normalization.** `parse_alert(raw_dict) -> AlertModel`. Validates required fields, maps `type` string to `AlertType` enum (suspicious_login, malware_detected, data_exfiltration, etc.). |
| `agent/tools.py` | **Four LangChain tools:** `search_threat_intel` (ChromaDB vector search), `check_login_history` (user/IP baseline), `check_impossible_travel` (Haversine physics), `lookup_file_hash` (malware signature DB). |
| `agent/retriever.py` | **ChromaDB wrapper.** `ThreatIntelRetriever` singleton with OpenAI embeddings. `query(text, k)` for semantic search, `add_documents()` for ingestion. |
| `agent/guardrails.py` | **Safety layer.** Pre-flight: `check_prompt_injection()`. Post-flight: `run_all_postflight()` — validates severity, gates low-confidence verdicts to `HUMAN_REVIEW`. |
| `agent/router.py` | **SOAR router.** Maps severity to `soar_action` — `AUTO_RESPOND` (HIGH+), `LOG_AND_MONITOR` (LOW/MEDIUM), `HUMAN_REVIEW`. Adds SLA strings. |

---

### `eval/` Package — Evaluation Framework

| File | Purpose |
|------|---------|
| `eval/dataset_builder.py` | Generates 100 synthetic labeled alerts with ground-truth severity across 7 alert types. Realistic distribution: CRITICAL 15%, HIGH 30%, MEDIUM 25%, LOW 30%. |
| `eval/runner.py` | `run_evaluation(model, limit)` — loads dataset, runs each alert through `SecurityAgent`, saves results to `eval/results/` as timestamped JSON. |
| `eval/metrics.py` | `compute_all_metrics()` — groundedness score, weighted precision/recall/F1, latency percentiles (mean/P50/P95/P99), cost projections (per-alert, daily, monthly), safety pass rate. |
| `eval/dashboard.py` | **4-page Streamlit dashboard** — Overview (KPI cards + bar charts), Model Comparison (side-by-side table + Plotly charts), Cost Analysis (interactive ROI slider vs human analysts), Live Demo (submit any alert JSON live). |

---

### `scripts/` Package

| File | Purpose |
|------|---------|
| `scripts/ingest_threat_intel.py` | Reads all `.txt` files from `data/threat_intel/`, splits into overlapping 400-char chunks (50-char overlap), hashes each chunk for deduplication, upserts into ChromaDB with OpenAI embeddings. Run once before first use. |

---

### `tests/` Package

| File | Purpose |
|------|---------|
| `tests/test_agent.py` | **23 unit tests** — zero API key required. Covers: alert parsing, unknown alert types, missing fields, prompt injection (case-insensitive), Haversine great-circle math, impossible travel detection, plausible travel, hash lookup (known/unknown/case-insensitive), confidence gating, severity validation, default field injection, SOAR routing for all 5 severity levels. |

---

### `data/` — Threat Intelligence

| File | What It Contains |
|------|-----------------|
| `data/threat_intel/mitre_attack.txt` | T1078 (Valid Accounts), T1090 (Proxy/Tor), T1110 (Brute Force), T1003 (Credential Dumping/Mimikatz), T1486 (Ransomware/WannaCry), T1071 (C2/Cobalt Strike), T1041 (Exfiltration), T1021 (Lateral Movement), T1548 (Privilege Escalation). Known malicious IP ranges included. |
| `data/threat_intel/malicious_ips.txt` | Tor exit nodes (185.220.101.45, /24 range), APT41 C2 server (203.0.113.45), scanning infrastructure (198.51.100.22), RFC1918 ranges with lateral-movement context. |
| `data/threat_intel/cves.txt` | EternalBlue (CVE-2017-0144), ProxyLogon (CVE-2021-26855), Confluence OGNL (CVE-2019-3396), Follina (CVE-2022-30190), Log4Shell (CVE-2021-44228), Outlook NTLM (CVE-2023-23397) with CVSS scores, affected versions, mitigations, patch priority guide. |

---

## 8. Quick Start — Python Commands

### Prerequisites

```bash
cd C:\Users\saisa\git-local\cybersecurity

# Install all dependencies
pip install -r requirements.txt

# .env must contain:
# OPENAI_API_KEY=sk-...
```

---

### All Commands

```bash
# ── 1. Ingest threat intel into ChromaDB ─────────────────────────────────────
python scripts/ingest_threat_intel.py
# Re-ingest: python scripts/ingest_threat_intel.py --force

# ── 2. Build evaluation dataset ──────────────────────────────────────────────
python -m eval.dataset_builder
# Custom count: python -m eval.dataset_builder --count 200

# ── 3. Run unit tests (no API key needed) ─────────────────────────────────────
python -m pytest tests/test_agent.py -v
# 23 tests, ~10 seconds, zero API cost

# ── 4. Run a single demo alert ────────────────────────────────────────────────
python agent.py --demo --model gpt-4o-mini
python agent.py --demo --model gpt-4o
python agent.py --demo --routing             # two-pass routing demo

# ── 5. Evaluate models ────────────────────────────────────────────────────────
python -m eval.runner --model gpt-4o-mini --limit 15
python -m eval.runner --model gpt-4o      --limit 10
python -m eval.runner --model gpt-4o-mini            # full 100-alert eval

# ── 6. Side-by-side model comparison ─────────────────────────────────────────
# via root alias:
python triage_alert.py --demo --compare-models
python model_comparison.py --limit 20 --save-report
# via skill path (canonical):
python skills/soc-triage-skill/scripts/triage_alert.py --demo --compare-models
python skills/eval-framework-skill/scripts/model_comparison.py --limit 20 --save-report

# ── 7. Search threat intel directly ──────────────────────────────────────────
# via root alias:
python search_intel.py "Tor exit node suspicious login" --top-k 3
python hash_lookup.py "5f4dcc3b5aa765d61d8327deb882cf99"
# via skill path (canonical):
python skills/threat-intel-skill/scripts/search_intel.py "T1078 credential access" --format text
python skills/threat-intel-skill/scripts/hash_lookup.py "d41d8cd98f00b204e9800998ecf8427e"

# ── 8. Launch Streamlit dashboard ─────────────────────────────────────────────
streamlit run eval/dashboard.py --server.port 8501
# Open: http://localhost:8501

# ── 9. Start FastAPI server ───────────────────────────────────────────────────
uvicorn main:app --reload --port 8000
# API docs: http://localhost:8000/docs

# ── 10. Call the REST API ─────────────────────────────────────────────────────

# Single alert with gpt-4o-mini:
curl -X POST "http://localhost:8000/analyze?model=gpt-4o-mini" \
  -H "Content-Type: application/json" \
  -d "{\"alert_id\":\"TEST-001\",\"type\":\"suspicious_login\",\"source_ip\":\"185.220.101.45\",\"location\":\"Romania\",\"prev_location\":\"New York, USA\",\"time_gap_hours\":2.0}"

# Two-pass routing:
curl -X POST "http://localhost:8000/analyze/routed" \
  -H "Content-Type: application/json" \
  -d "{\"alert_id\":\"TEST-002\",\"type\":\"malware_detected\",\"file_hash\":\"5f4dcc3b5aa765d61d8327deb882cf99\",\"hostname\":\"WORKSTATION-42\"}"

# Health check:
curl http://localhost:8000/health

# Model pricing:
curl http://localhost:8000/models
```

---

## 9. Run Everything (One Command)

```cmd
run.bat

 python -c "import subprocess; subprocess.run([r'C:\Users\saisa\git-local\cybersecurity\run.bat'], shell=True)"
```

The `run.bat` script executes the full pipeline in order:

```
[1/5]  pip install -r requirements.txt
[2/5]  python scripts/ingest_threat_intel.py
[3/5]  python -m eval.dataset_builder
[4/5]  python -m pytest tests/test_agent.py -v
[5/5]  python -m eval.runner --model gpt-4o-mini --limit 15
       python -m eval.runner --model gpt-4o --limit 10
       streamlit run eval/dashboard.py   <- opens at http://localhost:8501
```

**Requirements:** Python 3.10+, `OPENAI_API_KEY` in `.env`

---

## 10. Tech Stack

| Component | Technology | Why |
|-----------|-----------|-----|
| LLMs | GPT-4o + GPT-4o-mini | Best accuracy (4o) + 33x cheaper screening (mini) |
| Agent Framework | OpenAI Tool Calling API | Native, reliable, no framework version fragility |
| Tool Utilities | LangChain `@tool` decorator | Clean tool definition with automatic schema generation |
| Vector DB | ChromaDB (persistent) | Local, fast, no infra required, OpenAI embeddings |
| Embeddings | `text-embedding-3-small` | Best cost/quality ratio for semantic search |
| API | FastAPI + Uvicorn | Async, auto-docs at `/docs`, production-ready |
| Dashboard | Streamlit + Plotly | BI-quality interactive visualization in pure Python |
| Data Validation | Pydantic v2 | Type-safe alert parsing, fast validation |
| Testing | pytest | 23 deterministic unit tests, zero API cost |
| Skills Architecture | Anthropic Agent Skills | On-demand capability loading, lean context window |
| Threat Intel | MITRE ATT&CK, CVEs, IP feeds | Real-world grounding, updatable without retraining |

---

*Built to demonstrate production-grade AI security operations —
the same pattern used internally by Microsoft Security Copilot,
CrowdStrike Charlotte AI, and SentinelOne Purple AI.*
