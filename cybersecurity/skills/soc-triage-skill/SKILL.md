---
name: soc-triage-skill
description: >
  Analyze and triage security alerts using cybersecurity's AI-powered SOC agent.
  Supports GPT-4o (highest accuracy) and GPT-4o-mini (cost-optimized). Can run
  side-by-side model comparisons on a single alert. Use this skill when asked to
  analyze, triage, classify, or investigate a security alert.
triggers:
  - analyze alert
  - triage this alert
  - what severity is this
  - investigate this security event
  - SOC analysis
  - is this a real threat
  - should I escalate this
  - run triage
---

# SOC Triage Skill

Runs the full cybersecurity triage pipeline on a security alert — parsing,
prompt injection check, multi-tool reasoning (impossible travel, login history,
hash lookup, threat intel search), guardrails, and SOAR routing.

## When to Use

- Analyzing a raw security alert from Microsoft Sentinel, Splunk, or any SIEM
- Determining severity (LOW / MEDIUM / HIGH / CRITICAL) of a security event
- Getting recommended actions for a suspicious login, malware detection, or
  data exfiltration alert
- Running a side-by-side GPT-4o vs GPT-4o-mini comparison on one alert

## Scripts in This Skill

| Script | Purpose |
|--------|---------|
| `scripts/triage_alert.py` | Full triage pipeline with model selection and comparison mode |

---

## Usage

### Triage with default model (GPT-4o)

```bash
python skills/soc-triage-skill/scripts/triage_alert.py --demo
```

### Triage with GPT-4o-mini (33x cheaper, ~3x faster)

```bash
python skills/soc-triage-skill/scripts/triage_alert.py --demo --model gpt-4o-mini
```

### Triage a custom alert from a JSON file

```bash
python skills/soc-triage-skill/scripts/triage_alert.py --file alert.json
python skills/soc-triage-skill/scripts/triage_alert.py --file alert.json --model gpt-4o-mini
```

### Side-by-side model comparison on one alert

```bash
python skills/soc-triage-skill/scripts/triage_alert.py --demo --compare-models
```

---

## Alert JSON Format

```json
{
  "alert_id": "ALERT-001",
  "type": "suspicious_login",
  "user": "john.doe@company.com",
  "source_ip": "185.220.101.45",
  "location": "Romania",
  "prev_location": "New York, USA",
  "time_gap_hours": 2.0,
  "timestamp": "2024-01-15T03:14:00Z"
}
```

### Supported Alert Types

| type | Description | Key Fields |
|------|-------------|------------|
| `suspicious_login` | Anomalous login attempt | `user`, `source_ip`, `location`, `prev_location`, `time_gap_hours`, `failed_attempts` |
| `malware_detected` | Malware or suspicious binary | `hostname`, `file_hash`, `process_name`, `description` |
| `data_exfiltration` | Unusual outbound data transfer | `user`, `source_ip`, `destination_ip`, `description` |
| `privilege_escalation` | Unauthorized privilege gain | `user`, `hostname`, `description` |
| `lateral_movement` | Internal network spreading | `source_ip`, `destination_ip`, `description` |
| `network_anomaly` | Unusual network traffic pattern | `source_ip`, `destination_ip`, `description` |

---

## Output Format

```json
{
  "alert_id": "ALERT-001",
  "alert_type": "suspicious_login",
  "severity": "CRITICAL",
  "confidence": 0.92,
  "explanation": "Login from Romania 2h after New York login. Impossible travel confirmed (9,234 km at 4,617 kph). Source IP 185.220.101.45 is a known Tor exit node.",
  "recommended_actions": [
    "Reset user password immediately",
    "Enable MFA for john.doe@company.com",
    "Block IP 185.220.101.45 at perimeter firewall"
  ],
  "mitre_techniques": ["T1078", "T1090"],
  "grounding_sources": ["check_impossible_travel result", "check_login_history result"],
  "tool_calls_made": ["check_impossible_travel", "check_login_history"],
  "model_used": "gpt-4o",
  "latency_ms": 3241,
  "tokens_used": 987,
  "estimated_cost_usd": 0.00312,
  "soar_action": "AUTO_RESPOND",
  "soar_sla": "1 hour"
}
```

---

## Severity Definitions

| Severity | SLA | SOAR Action | Example |
|----------|-----|-------------|---------|
| `CRITICAL` | Immediate (< 15 min) | AUTO_RESPOND | Ransomware dropper, confirmed APT C2 |
| `HIGH` | 1 hour | AUTO_RESPOND | Impossible travel, Cobalt Strike beacon |
| `MEDIUM` | 24 hours | LOG_AND_MONITOR | Cross-country login, minor anomaly |
| `LOW` | Best effort | LOG_AND_MONITOR | Same-region login, benign PUP |
| `HUMAN_REVIEW` | Analyst queue | HUMAN_REVIEW | Low confidence, ambiguous evidence |

---

## Tool Call Behavior

The agent automatically selects which tools to call based on alert type:

```
suspicious_login  -> check_impossible_travel + check_login_history + (search_threat_intel)
malware_detected  -> lookup_file_hash + search_threat_intel
data_exfiltration -> check_login_history + search_threat_intel
lateral_movement  -> search_threat_intel + check_login_history
any type          -> search_threat_intel (always considered)
```

---

## Model Selection Guide

| Use Case | Recommended Model | Reason |
|----------|-------------------|--------|
| HIGH / CRITICAL alerts | `gpt-4o` | Maximum accuracy, nuanced reasoning |
| LOW / MEDIUM alerts | `gpt-4o-mini` | 33x cheaper, 3x faster, sufficient accuracy |
| High-volume screening | `gpt-4o-mini` | Cost-efficient for initial triage |
| Production (smart routing) | `--routing` flag | Automatic escalation from mini to 4o |
