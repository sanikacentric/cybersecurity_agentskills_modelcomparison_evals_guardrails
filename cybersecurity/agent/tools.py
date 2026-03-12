"""
agent/tools.py — LangChain tools for the SecurityAgent ReAct loop.

Tools:
  search_threat_intel     → semantic search over ChromaDB threat intel
  check_login_history     → login history lookup (simulated)
  check_impossible_travel → physics-based travel plausibility check
  lookup_file_hash        → malware hash DB lookup
"""

from __future__ import annotations
import json
import math
from langchain.tools import tool

# ── Malware hash database (matches hash_lookup.py) ────────────────────────────
KNOWN_MALWARE: dict[str, dict] = {
    "d41d8cd98f00b204e9800998ecf8427e": {
        "name": "Mimikatz", "category": "credential_stealer",
        "severity": "CRITICAL", "mitre": "T1003",
        "description": "Password dumping tool used in APT campaigns and ransomware pre-staging.",
    },
    "5f4dcc3b5aa765d61d8327deb882cf99": {
        "name": "WannaCry Dropper", "category": "ransomware",
        "severity": "CRITICAL", "mitre": "T1486",
        "description": "WannaCry ransomware dropper. Exploits EternalBlue (MS17-010). Self-propagating.",
    },
    "abc123def456789012345678901234ab": {
        "name": "Cobalt Strike Beacon", "category": "c2_agent",
        "severity": "HIGH", "mitre": "T1071",
        "description": "Commercial red team tool widely abused for C2 communication.",
    },
    "098f6bcd4621d373cade4e832627b4f6": {
        "name": "Generic Adware", "category": "adware",
        "severity": "LOW", "mitre": "T1176",
        "description": "Low-risk adware. Unwanted but not immediately dangerous.",
    },
}

# ── Known malicious IP ranges/addresses ───────────────────────────────────────
KNOWN_BAD_IPS: dict[str, dict] = {
    "185.220.101.45": {
        "reputation": "MALICIOUS", "category": "Tor exit node",
        "country": "Romania", "threat_level": "HIGH",
        "description": "Known Tor exit node used for anonymized attacks.",
    },
    "185.220.101.0":  {
        "reputation": "SUSPICIOUS", "category": "Tor exit node range",
        "country": "Germany", "threat_level": "HIGH",
        "description": "Tor exit node range — common source of credential-stuffing attacks.",
    },
    "192.168.1.100":  {
        "reputation": "INTERNAL", "category": "internal_host",
        "country": "N/A", "threat_level": "LOW",
        "description": "Internal IP address — monitor for lateral movement indicators.",
    },
    "10.0.0.50": {
        "reputation": "INTERNAL", "category": "internal_server",
        "country": "N/A", "threat_level": "LOW",
        "description": "Internal server IP.",
    },
    "203.0.113.45": {
        "reputation": "MALICIOUS", "category": "known_c2",
        "country": "China", "threat_level": "CRITICAL",
        "description": "Known C2 server associated with APT41 campaigns.",
    },
}

# ── Simulated login history ────────────────────────────────────────────────────
SIMULATED_LOGIN_HISTORY: dict[str, dict] = {
    "john.doe@company.com": {
        "usual_locations": ["New York, USA", "Boston, USA"],
        "usual_hours": "09:00-18:00 EST",
        "recent_failed_attempts": 0,
        "last_successful_login": "2024-01-14T17:30:00Z",
        "last_location": "New York, USA",
        "risk_notes": "Normal behavior. No anomalies in last 30 days.",
    },
    "admin@company.com": {
        "usual_locations": ["San Francisco, USA"],
        "usual_hours": "08:00-20:00 PST",
        "recent_failed_attempts": 3,
        "last_successful_login": "2024-01-13T14:00:00Z",
        "last_location": "San Francisco, USA",
        "risk_notes": "3 failed attempts in last 24h. Monitor closely.",
    },
    "jane.smith@company.com": {
        "usual_locations": ["London, UK"],
        "usual_hours": "08:00-17:00 GMT",
        "recent_failed_attempts": 0,
        "last_successful_login": "2024-01-15T09:00:00Z",
        "last_location": "London, UK",
        "risk_notes": "Normal behavior.",
    },
}

# ── Approximate city coordinates for travel-speed math ────────────────────────
CITY_COORDS: dict[str, tuple[float, float]] = {
    "new york":       (40.71, -74.01),
    "new york, usa":  (40.71, -74.01),
    "boston":         (42.36, -71.06),
    "boston, usa":    (42.36, -71.06),
    "london":         (51.51, -0.13),
    "london, uk":     (51.51, -0.13),
    "romania":        (45.94, 24.97),
    "bucharest":      (44.43, 26.10),
    "san francisco":  (37.77, -122.42),
    "tokyo":          (35.68, 139.69),
    "beijing":        (39.91, 116.39),
    "moscow":         (55.76, 37.62),
    "berlin":         (52.52, 13.40),
    "paris":          (48.86, 2.35),
    "sydney":         (-33.87, 151.21),
    "dubai":          (25.20, 55.27),
}

MAX_HUMAN_SPEED_KPH = 1000  # ~max commercial flight speed


def _haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in km."""
    R = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


# ── LangChain tools ────────────────────────────────────────────────────────────

@tool
def search_threat_intel(query: str) -> str:
    """
    Search the threat intelligence database for information about IPs, file hashes,
    MITRE ATT&CK techniques, malware families, or attack patterns.
    Input: a natural language query or specific indicator (IP, hash, technique ID).
    """
    from agent.retriever import get_retriever
    retriever = get_retriever()

    if retriever._collection.count() == 0:
        # Fallback: check known bad IPs inline
        query_lower = query.lower()
        for ip, data in KNOWN_BAD_IPS.items():
            if ip in query_lower:
                return json.dumps({"source": "inline_db", "result": data}, indent=2)
        return json.dumps({
            "note": "Threat intel DB is empty. Run: python scripts/ingest_threat_intel.py",
            "query": query,
            "results": [],
        })

    results = retriever.query(query, k=5)
    return json.dumps({"query": query, "results": results}, indent=2)


@tool
def check_login_history(user_or_ip: str) -> str:
    """
    Check login history and baseline behavior for a user email or IP address.
    Returns usual locations, login hours, recent failed attempts, and risk notes.
    Input: user email (e.g. john.doe@company.com) or IP address.
    """
    key = user_or_ip.strip().lower()

    # Check if it's an IP
    for ip, data in KNOWN_BAD_IPS.items():
        if ip == key or ip in key:
            return json.dumps({
                "query": user_or_ip,
                "type": "ip_lookup",
                "result": data,
            }, indent=2)

    # Check user history
    for email, history in SIMULATED_LOGIN_HISTORY.items():
        if email.lower() == key or email.lower() in key:
            return json.dumps({
                "query": user_or_ip,
                "type": "user_history",
                "result": history,
            }, indent=2)

    return json.dumps({
        "query": user_or_ip,
        "result": "No history found. First-time entity or not in local DB.",
        "risk_notes": "Unknown entity — treat as elevated risk.",
    }, indent=2)


@tool
def check_impossible_travel(params: str) -> str:
    """
    Determine whether a login represents physically impossible travel.
    Input: JSON string or plain text describing current_location, prev_location, time_gap_hours.
    Example: '{"current_location": "Romania", "prev_location": "New York, USA", "time_gap_hours": 2.0}'
    Returns: distance_km, required_speed_kph, is_impossible, risk_assessment.
    """
    # Parse input — accept JSON or key=value text
    try:
        data = json.loads(params)
    except (json.JSONDecodeError, TypeError):
        # Try to extract from plain text
        data = {}
        for line in str(params).replace(",", "\n").split("\n"):
            for key in ("current_location", "prev_location", "time_gap_hours",
                        "location", "prev_location"):
                if key in line.lower():
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        val = parts[1].strip().strip('"').strip("'")
                        data[key] = val

    current = str(data.get("current_location") or data.get("location", "")).lower().strip()
    prev    = str(data.get("prev_location", "")).lower().strip()

    try:
        gap_hours = float(data.get("time_gap_hours", 1.0))
    except (ValueError, TypeError):
        gap_hours = 1.0

    curr_coords = next((v for k, v in CITY_COORDS.items() if k in current or current in k), None)
    prev_coords = next((v for k, v in CITY_COORDS.items() if k in prev or prev in k), None)

    if not curr_coords or not prev_coords:
        return json.dumps({
            "current_location": current,
            "prev_location":    prev,
            "time_gap_hours":   gap_hours,
            "note":             "Could not resolve coordinates. Treat as suspicious if locations are far apart.",
            "is_impossible":    None,
            "risk_assessment":  "MEDIUM — manual verification required.",
        }, indent=2)

    distance_km     = _haversine(*prev_coords, *curr_coords)
    required_speed  = distance_km / max(gap_hours, 0.01)
    is_impossible   = required_speed > MAX_HUMAN_SPEED_KPH

    if is_impossible:
        risk = "HIGH — physically impossible travel detected. Likely credential compromise."
    elif required_speed > 800:
        risk = "MEDIUM — very fast travel. Only possible by direct flight. Verify with user."
    elif distance_km > 5000:
        risk = "MEDIUM — large geographic distance. International travel should be verified."
    else:
        risk = "LOW — travel speed is plausible."

    return json.dumps({
        "current_location":    current,
        "prev_location":       prev,
        "time_gap_hours":      gap_hours,
        "distance_km":         round(distance_km, 1),
        "required_speed_kph":  round(required_speed, 1),
        "max_human_speed_kph": MAX_HUMAN_SPEED_KPH,
        "is_impossible":       is_impossible,
        "risk_assessment":     risk,
    }, indent=2)


@tool
def lookup_file_hash(file_hash: str) -> str:
    """
    Look up a file hash (MD5, SHA1, or SHA256) against the malware signature database.
    Returns malware name, category, severity, and MITRE technique if found.
    Input: hex hash string.
    """
    normalized = file_hash.strip().lower()
    hit = KNOWN_MALWARE.get(normalized)

    if hit:
        return json.dumps({
            "hash":               file_hash,
            "status":             "MALICIOUS",
            "malware_name":       hit["name"],
            "category":           hit["category"],
            "severity":           hit["severity"],
            "mitre_technique":    hit["mitre"],
            "description":        hit["description"],
            "recommended_action": "ISOLATE endpoint immediately and begin incident response.",
        }, indent=2)
    else:
        return json.dumps({
            "hash":               file_hash,
            "status":             "NOT_FOUND",
            "note":               "Hash not in local DB. Query VirusTotal or Defender ATP for production use.",
            "recommended_action": "Submit to VirusTotal for community analysis.",
        }, indent=2)


ALL_TOOLS = [
    search_threat_intel,
    check_login_history,
    check_impossible_travel,
    lookup_file_hash,
]
