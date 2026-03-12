"""
api/main.py — FastAPI Application

ENDPOINTS:
  POST /analyze          → Analyze alert (supports ?model=gpt-4o-mini)
  POST /analyze/batch    → Analyze multiple alerts
  POST /analyze/routed   → Two-pass routing (mini first, 4o if HIGH/CRITICAL)
  GET  /health           → Health check
  GET  /metrics          → Latest eval metrics
  GET  /models           → Model info and pricing
"""

from __future__ import annotations
import json
from pathlib import Path
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
import uvicorn

from config import EVAL_RESULTS_DIR, MODEL_PRICING

_agent_cache: dict = {}

def get_agent(model: str = "gpt-4o"):
    """Get or create a cached SecurityAgent for the given model."""
    if model not in _agent_cache:
        from agent.agent import SecurityAgent
        _agent_cache[model] = SecurityAgent(model=model)
    return _agent_cache[model]


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[*] cybersecurity API starting — warming up agents...")
    get_agent("gpt-4o")
    get_agent("gpt-4o-mini")
    print("[OK] Both agents ready")
    yield
    print("[*] cybersecurity API shutting down")


app = FastAPI(
    title="cybersecurity Security Agent API",
    description="AI-powered security alert triage — GPT-4o + GPT-4o-mini + RAG + Guardrails",
    version="2.0.0",
    lifespan=lifespan,
)


class AlertRequest(BaseModel):
    alert_id:        str
    type:            str
    user:            Optional[str]   = None
    source_ip:       Optional[str]   = None
    destination_ip:  Optional[str]   = None
    hostname:        Optional[str]   = None
    location:        Optional[str]   = None
    prev_location:   Optional[str]   = None
    time_gap_hours:  Optional[float] = None
    failed_attempts: Optional[int]   = None
    file_hash:       Optional[str]   = None
    process_name:    Optional[str]   = None
    description:     Optional[str]   = None
    timestamp:       Optional[str]   = None


class BatchRequest(BaseModel):
    alerts: List[AlertRequest]
    model:  Optional[str] = "gpt-4o"


@app.get("/health")
async def health():
    from agent.retriever import get_retriever
    doc_count = get_retriever()._collection.count()
    return {
        "status":            "healthy",
        "agents_loaded":     list(_agent_cache.keys()),
        "threat_intel_docs": doc_count,
    }


@app.get("/models")
async def list_models():
    """Returns available models and their pricing."""
    return {
        "models": {
            "gpt-4o": {
                "description": "Highest accuracy. Recommended for HIGH/CRITICAL alerts.",
                "pricing":     MODEL_PRICING["gpt-4o"],
                "use_case":    "Production triage, critical decisions",
            },
            "gpt-4o-mini": {
                "description": "Cost-optimized. 33x cheaper input tokens, ~3x faster.",
                "pricing":     MODEL_PRICING["gpt-4o-mini"],
                "use_case":    "High-volume screening, LOW/MEDIUM alerts",
            },
        },
        "routing_strategy": {
            "description": "Use /analyze/routed for automatic two-pass routing",
            "pass1": "gpt-4o-mini screens all alerts",
            "pass2": "gpt-4o re-analyzes HIGH/CRITICAL from Pass 1",
            "estimated_savings": "~60% vs all-gpt-4o",
        }
    }


@app.post("/analyze")
async def analyze_alert(
    request: AlertRequest,
    model: str = Query(default="gpt-4o", description="Model: gpt-4o or gpt-4o-mini"),
):
    """
    Analyze a single security alert.

    Pass `?model=gpt-4o-mini` for cost-optimized analysis (~33x cheaper).

    Example:
    ```
    POST /analyze?model=gpt-4o-mini
    {
      "alert_id": "ALT-001",
      "type": "suspicious_login",
      "source_ip": "185.220.101.45",
      "location": "Romania",
      "prev_location": "New York",
      "time_gap_hours": 2.0
    }
    ```
    """
    if model not in MODEL_PRICING:
        raise HTTPException(400, f"Unknown model '{model}'. Use: {list(MODEL_PRICING.keys())}")

    agent  = get_agent(model)
    raw    = request.model_dump(exclude_none=True)
    result = agent.analyze(raw)

    if result.get("error") and not result.get("severity"):
        raise HTTPException(422, result["error"])

    return result


@app.post("/analyze/routed")
async def analyze_routed(request: AlertRequest):
    """
    Two-pass routing: gpt-4o-mini screens first, gpt-4o re-analyzes HIGH/CRITICAL.
    Returns result with routing_escalated flag and total_cost_usd breakdown.
    """
    agent  = get_agent("gpt-4o-mini")  # Pass 1 model; escalator uses gpt-4o internally
    raw    = request.model_dump(exclude_none=True)
    result = agent.analyze_with_routing(raw)
    return result


@app.post("/analyze/batch")
async def analyze_batch(request: BatchRequest):
    """Analyze multiple alerts. Supports model selection via body.model field."""
    model = request.model or "gpt-4o"
    if model not in MODEL_PRICING:
        raise HTTPException(400, f"Unknown model '{model}'")
    if len(request.alerts) > 50:
        raise HTTPException(400, "Batch limited to 50 alerts")

    agent   = get_agent(model)
    results = [agent.analyze(a.model_dump(exclude_none=True)) for a in request.alerts]
    return {"model": model, "processed": len(results), "results": results}


@app.get("/metrics")
async def get_metrics():
    metric_files = sorted(Path(EVAL_RESULTS_DIR).glob("metrics_*.json"))
    if not metric_files:
        return {"message": "No results yet. Run: python -m eval.runner"}
    with open(metric_files[-1]) as f:
        return json.load(f)


if __name__ == "__main__":
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
