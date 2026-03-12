"""
config.py — Central configuration for cybersecurity.
All model names, thresholds, paths, and constants live here.
Change model or tweak thresholds in ONE place.

MODELS SUPPORTED:
  LLM_MODEL = "gpt-4o"       → Highest accuracy, used for HIGH/CRITICAL triage
  LLM_MODEL = "gpt-4o-mini"  → 33x cheaper input tokens, good for LOW/MEDIUM triage

AGENT SKILLS:
  Skills live under skills/ directory. Each skill has a SKILL.md with
  YAML frontmatter (name + description) and optional scripts/ for execution.
  See skills/ directory for: threat-intel-skill, soc-triage-skill,
  eval-framework-skill, model-comparison-skill
"""

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR        = Path(__file__).parent
DATA_DIR        = BASE_DIR / "data"
THREAT_INTEL_DIR = DATA_DIR / "threat_intel"
SYNTHETIC_DIR   = DATA_DIR / "synthetic_alerts"
CHROMA_DIR      = BASE_DIR / ".chromadb"
SKILLS_DIR      = BASE_DIR / "skills"

# ── LLM ───────────────────────────────────────────────────────────────────────
OPENAI_API_KEY   = os.getenv("OPENAI_API_KEY", "")

# Primary model — change here to switch globally, or override per-request
# "gpt-4o"      → Best accuracy, ~$0.005/1K input tokens
# "gpt-4o-mini" → Best cost,     ~$0.00015/1K input tokens (33x cheaper)
LLM_MODEL        = os.getenv("SECUREMIND_MODEL", "gpt-4o")

EMBEDDING_MODEL  = "text-embedding-3-small"
MAX_TOKENS       = 1500
TEMPERATURE      = 0.1   # Low = deterministic, consistent verdicts

# ── Model Pricing (per 1K tokens, USD) ────────────────────────────────────────
# Used by eval/metrics.py for cost-per-alert calculations
MODEL_PRICING = {
    "gpt-4o": {
        "input":  0.005,    # $5.00 / 1M tokens
        "output": 0.015,    # $15.00 / 1M tokens
    },
    "gpt-4o-mini": {
        "input":  0.000150, # $0.15 / 1M tokens  (33x cheaper than 4o)
        "output": 0.000600, # $0.60 / 1M tokens  (25x cheaper than 4o)
    },
}

# Resolved pricing for current model (used by metrics.py)
_pricing             = MODEL_PRICING.get(LLM_MODEL, MODEL_PRICING["gpt-4o"])
COST_PER_1K_INPUT_TOKENS  = _pricing["input"]
COST_PER_1K_OUTPUT_TOKENS = _pricing["output"]

# ── RAG ───────────────────────────────────────────────────────────────────────
CHROMA_COLLECTION = "threat_intel"
TOP_K_RETRIEVAL   = 5    # Chunks returned per vector query
CHUNK_SIZE        = 400
CHUNK_OVERLAP     = 50

# ── Agent ─────────────────────────────────────────────────────────────────────
CONFIDENCE_THRESHOLD  = 0.65   # Below this → route to HUMAN_REVIEW
MAX_AGENT_ITERATIONS  = 6      # Prevent runaway tool-call loops

# ── Model Routing Strategy ────────────────────────────────────────────────────
# For the two-pass routing strategy (see model-comparison-skill/SKILL.md):
#   Pass 1: gpt-4o-mini for all alerts (fast, cheap)
#   Pass 2: gpt-4o re-analysis for HIGH+ from Pass 1 (accurate)
ROUTING_ENABLED             = os.getenv("SECUREMIND_ROUTING", "false").lower() == "true"
ROUTING_ESCALATION_THRESHOLD = "HIGH"   # Severities that trigger Pass 2

# ── Severity Routing ──────────────────────────────────────────────────────────
SEVERITY_LEVELS         = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
AUTO_RESPOND_THRESHOLD  = "HIGH"   # AUTO SOAR action only for HIGH+

# ── Evaluation ────────────────────────────────────────────────────────────────
EVAL_DATASET_PATH = SYNTHETIC_DIR / "test_dataset.json"
EVAL_RESULTS_DIR  = BASE_DIR / "eval" / "results"
EVAL_NUM_ALERTS   = 100

# ── Safety ────────────────────────────────────────────────────────────────────
INJECTION_KEYWORDS = [
    "ignore previous instructions",
    "disregard above",
    "new instructions:",
    "system:",
    "jailbreak",
    "forget your rules",
]
