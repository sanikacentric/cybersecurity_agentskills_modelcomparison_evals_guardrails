"""
agent/agent.py — Main Security Agent Orchestrator (OpenAI Tool Calling)

Uses OpenAI's native function/tool-calling API in a ReAct-style loop
instead of LangChain AgentExecutor (removed in langchain 1.x).

MODEL SELECTION:
  model="gpt-4o"      -> Highest accuracy (default, recommended for HIGH/CRITICAL)
  model="gpt-4o-mini" -> 33x cheaper input tokens (good for LOW/MEDIUM volume)

TWO-PASS ROUTING:
  analyze_with_routing() runs mini first, escalates HIGH/CRITICAL to gpt-4o.
"""

from __future__ import annotations
import json
import time
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from openai import OpenAI

from agent.parser import AlertModel, parse_alert
from agent.guardrails import check_prompt_injection, run_all_postflight
from agent.router import route_verdict
import config
from config import (
    MAX_TOKENS, TEMPERATURE, OPENAI_API_KEY, MAX_AGENT_ITERATIONS,
    MODEL_PRICING, ROUTING_ESCALATION_THRESHOLD, SEVERITY_LEVELS,
)

# ── Tool definitions (OpenAI function-calling schema) ─────────────────────────

TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "search_threat_intel",
            "description": (
                "Search the threat intelligence database for information about IPs, "
                "file hashes, MITRE ATT&CK techniques, malware families, or attack patterns."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query: IP address, hash, technique ID, or natural language.",
                    }
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_login_history",
            "description": (
                "Check login history and baseline behavior for a user email or IP address. "
                "Returns usual locations, login hours, recent failed attempts, and risk notes."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "user_or_ip": {
                        "type": "string",
                        "description": "User email (e.g. john.doe@company.com) or IP address.",
                    }
                },
                "required": ["user_or_ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_impossible_travel",
            "description": (
                "Determine whether a login represents physically impossible travel. "
                "Checks if the required travel speed exceeds what is physically achievable."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "current_location": {
                        "type": "string",
                        "description": "Current login location (city, country).",
                    },
                    "prev_location": {
                        "type": "string",
                        "description": "Previous login location (city, country).",
                    },
                    "time_gap_hours": {
                        "type": "number",
                        "description": "Hours between the two logins.",
                    },
                },
                "required": ["current_location", "prev_location", "time_gap_hours"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_file_hash",
            "description": (
                "Look up a file hash (MD5, SHA1, or SHA256) against the malware signature database. "
                "Returns malware name, category, severity, and MITRE technique if found."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "file_hash": {
                        "type": "string",
                        "description": "The hex hash string to look up.",
                    }
                },
                "required": ["file_hash"],
            },
        },
    },
]

SYSTEM_PROMPT = """You are cybersecurity, a senior Tier-1 SOC analyst AI.

RULES:
1. Always use at least one tool before forming a conclusion.
2. For suspicious_login: ALWAYS call check_impossible_travel and check_login_history.
3. For malware_detected: ALWAYS call lookup_file_hash and search_threat_intel.
4. For any alert: consider calling search_threat_intel with the attack pattern.
5. Base every claim on evidence from tool results — never speculate.
6. Your FINAL response (when you have enough evidence) must be a JSON object ONLY:

{
  "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "confidence": 0.0 to 1.0,
  "explanation": "1-3 sentence explanation citing specific evidence from tools",
  "recommended_actions": ["action1", "action2", "action3"],
  "mitre_techniques": ["T1078", "T1090"],
  "grounding_sources": ["tool_result_1", "tool_result_2"]
}

SEVERITY: LOW=benign, MEDIUM=24hr SLA, HIGH=1hr SLA, CRITICAL=immediate
In security, false negatives (missed attacks) are worse than false positives.
Output ONLY the JSON object when done — no extra text."""


# ── Tool dispatcher ───────────────────────────────────────────────────────────

def _dispatch_tool(name: str, args: dict) -> str:
    """Execute a tool by name with parsed args. Returns JSON string."""
    from agent.tools import (
        search_threat_intel, check_login_history,
        check_impossible_travel, lookup_file_hash,
    )
    if name == "search_threat_intel":
        return search_threat_intel.invoke(args["query"])
    elif name == "check_login_history":
        return check_login_history.invoke(args["user_or_ip"])
    elif name == "check_impossible_travel":
        return check_impossible_travel.invoke(json.dumps(args))
    elif name == "lookup_file_hash":
        return lookup_file_hash.invoke(args["file_hash"])
    else:
        return json.dumps({"error": f"Unknown tool: {name}"})


# ── Alert text builder ────────────────────────────────────────────────────────

def _alert_to_text(alert: AlertModel) -> str:
    lines = [f"ALERT ID: {alert.alert_id}", f"ALERT TYPE: {alert.alert_type.value}"]
    if alert.user:            lines.append(f"USER: {alert.user}")
    if alert.source_ip:       lines.append(f"SOURCE IP: {alert.source_ip}")
    if alert.destination_ip:  lines.append(f"DESTINATION IP: {alert.destination_ip}")
    if alert.hostname:        lines.append(f"HOSTNAME: {alert.hostname}")
    if alert.location:        lines.append(f"CURRENT LOCATION: {alert.location}")
    if alert.prev_location:   lines.append(f"PREVIOUS LOCATION: {alert.prev_location}")
    if alert.time_gap_hours:  lines.append(f"TIME GAP (hours): {alert.time_gap_hours}")
    if alert.failed_attempts: lines.append(f"FAILED LOGIN ATTEMPTS: {alert.failed_attempts}")
    if alert.file_hash:       lines.append(f"FILE HASH: {alert.file_hash}")
    if alert.process_name:    lines.append(f"PROCESS NAME: {alert.process_name}")
    if alert.raw_description: lines.append(f"DESCRIPTION: {alert.raw_description}")
    if alert.timestamp:       lines.append(f"TIMESTAMP: {alert.timestamp}")
    return "\n".join(lines)


def _estimate_cost(model: str, tokens_used: int) -> float:
    pricing = MODEL_PRICING.get(model, MODEL_PRICING["gpt-4o"])
    return (tokens_used * 0.7 / 1000) * pricing["input"] + \
           (tokens_used * 0.3 / 1000) * pricing["output"]


def _error_result(msg: str, alert_id: str) -> dict:
    return {
        "alert_id":            alert_id,
        "severity":            "HUMAN_REVIEW",
        "confidence":          0.0,
        "explanation":         f"Agent error: {msg}",
        "recommended_actions": ["Manually review", "Check logs"],
        "error":               msg,
        "guardrail_triggered": True,
    }


# ── Core agentic loop ─────────────────────────────────────────────────────────

def _run_agent(client: OpenAI, model: str, alert_text: str, alert_id: str) -> dict:
    """
    Run the tool-calling agentic loop until the model produces a final JSON verdict
    or MAX_AGENT_ITERATIONS is reached.
    """
    start    = time.time()
    messages = [
        {"role": "system",  "content": SYSTEM_PROMPT},
        {"role": "user",    "content": f"Analyze this security alert:\n\n{alert_text}"},
    ]
    tool_calls_made = []
    total_tokens    = 0

    for iteration in range(MAX_AGENT_ITERATIONS):
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            tools=TOOLS_SCHEMA,
            tool_choice="auto",
            max_tokens=MAX_TOKENS,
            temperature=TEMPERATURE,
        )
        choice        = response.choices[0]
        total_tokens += response.usage.total_tokens if response.usage else 0
        messages.append(choice.message)

        # If the model wants to call tools
        if choice.finish_reason == "tool_calls" and choice.message.tool_calls:
            for tc in choice.message.tool_calls:
                tool_name = tc.function.name
                tool_args = json.loads(tc.function.arguments)
                tool_calls_made.append(tool_name)

                print(f"    [tool] {tool_name}({tool_args})")
                result = _dispatch_tool(tool_name, tool_args)

                messages.append({
                    "role":         "tool",
                    "tool_call_id": tc.id,
                    "content":      result,
                })
            continue  # let model process tool results

        # Model is done — extract final JSON
        raw_output = choice.message.content or ""
        try:
            # Try direct parse
            verdict = json.loads(raw_output.strip())
        except json.JSONDecodeError:
            # Try to extract JSON block from markdown
            import re
            match = re.search(r'\{.*\}', raw_output, re.DOTALL)
            if match:
                try:
                    verdict = json.loads(match.group())
                except json.JSONDecodeError:
                    return _error_result(f"Unparseable output: {raw_output[:200]}", alert_id)
            else:
                return _error_result(f"No JSON in output: {raw_output[:200]}", alert_id)

        verdict.update({
            "alert_id":           alert_id,
            "model_used":         model,
            "latency_ms":         int((time.time() - start) * 1000),
            "tokens_used":        total_tokens,
            "tool_calls_made":    tool_calls_made,
            "estimated_cost_usd": round(_estimate_cost(model, total_tokens), 6),
        })
        return verdict

    return _error_result("Max iterations reached without final verdict", alert_id)


# ── SecurityAgent class ───────────────────────────────────────────────────────

class SecurityAgent:
    """
    cybersecurity triage agent. Supports GPT-4o and GPT-4o-mini.

    Usage:
        agent = SecurityAgent()                          # GPT-4o (default)
        agent = SecurityAgent(model="gpt-4o-mini")       # Cost-optimized
        result = agent.analyze(raw_alert_dict)
        result = agent.analyze_with_routing(raw_alert_dict)  # Two-pass
    """

    def __init__(self, model: str = None) -> None:
        self.model  = model or config.LLM_MODEL
        self.client = OpenAI(api_key=OPENAI_API_KEY)

    def analyze(self, raw_alert: dict) -> dict:
        """Analyze a single raw alert dict. Returns structured triage verdict."""
        try:
            alert = parse_alert(raw_alert)
        except ValueError as e:
            return _error_result(str(e), raw_alert.get("alert_id", "UNKNOWN"))

        alert_text = _alert_to_text(alert)
        try:
            check_prompt_injection(alert_text)
        except Exception as e:
            return _error_result(str(e), alert.alert_id)

        verdict = _run_agent(self.client, self.model, alert_text, alert.alert_id)
        verdict["alert_type"] = alert.alert_type.value
        return route_verdict(run_all_postflight(verdict))

    def analyze_with_routing(self, raw_alert: dict) -> dict:
        """
        Two-pass triage:
          Pass 1 - gpt-4o-mini (all alerts, cheap screening)
          Pass 2 - gpt-4o (only HIGH/CRITICAL from Pass 1)
        ~60% cost reduction vs running gpt-4o on everything.
        """
        try:
            alert = parse_alert(raw_alert)
        except ValueError as e:
            return _error_result(str(e), raw_alert.get("alert_id", "UNKNOWN"))

        alert_text = _alert_to_text(alert)
        try:
            check_prompt_injection(alert_text)
        except Exception as e:
            return _error_result(str(e), alert.alert_id)

        # Pass 1: always gpt-4o-mini
        pass1 = _run_agent(self.client, "gpt-4o-mini", alert_text, alert.alert_id)
        pass1["alert_type"] = alert.alert_type.value

        sev_order     = {s: i for i, s in enumerate(SEVERITY_LEVELS)}
        threshold_idx = sev_order.get(ROUTING_ESCALATION_THRESHOLD, 2)
        predicted_idx = sev_order.get(pass1.get("severity", "LOW"), 0)

        if predicted_idx >= threshold_idx:
            print(f"  [^] Routing: {pass1.get('severity')} -> escalating to gpt-4o")
            pass2 = _run_agent(self.client, "gpt-4o", alert_text, alert.alert_id)
            pass2["alert_type"]        = alert.alert_type.value
            pass2["routing_used"]      = True
            pass2["routing_escalated"] = True
            pass2["pass1_severity"]    = pass1.get("severity")
            pass2["pass1_cost_usd"]    = pass1.get("estimated_cost_usd", 0)
            pass2["total_cost_usd"]    = (pass1.get("estimated_cost_usd", 0) +
                                          pass2.get("estimated_cost_usd", 0))
            return route_verdict(run_all_postflight(pass2))
        else:
            pass1["routing_used"]      = True
            pass1["routing_escalated"] = False
            pass1["total_cost_usd"]    = pass1.get("estimated_cost_usd", 0)
            return route_verdict(run_all_postflight(pass1))


# ── CLI Demo ──────────────────────────────────────────────────────────────────
DEMO_ALERT = {
    "alert_id": "DEMO-001", "type": "suspicious_login",
    "user": "john.doe@company.com", "source_ip": "185.220.101.45",
    "location": "Romania", "prev_location": "New York, USA",
    "time_gap_hours": 2.0, "timestamp": "2024-01-15T03:14:00Z",
}

if __name__ == "__main__":
    import argparse, pprint
    parser = argparse.ArgumentParser()
    parser.add_argument("--demo",    action="store_true")
    parser.add_argument("--model",   default="gpt-4o", choices=["gpt-4o", "gpt-4o-mini"])
    parser.add_argument("--routing", action="store_true", help="Use two-pass routing")
    args = parser.parse_args()

    if args.demo:
        print(f"\ncybersecurity Demo - model={args.model}\n")
        agent  = SecurityAgent(model=args.model)
        result = (agent.analyze_with_routing(DEMO_ALERT) if args.routing
                  else agent.analyze(DEMO_ALERT))
        print("\n" + "=" * 60 + "\nTRIAGE RESULT:\n" + "=" * 60)
        pprint.pprint(result)
