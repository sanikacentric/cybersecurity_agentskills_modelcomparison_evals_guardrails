---
name: threat-intel-skill
description: Search and retrieve cybersecurity threat intelligence from the cybersecurity vector database. Use this skill when analyzing security alerts, looking up malicious IPs, checking file hashes, querying MITRE ATT&CK techniques, or retrieving CVE vulnerability data. Triggers on: IP reputation lookup, hash check, threat intel search, MITRE technique lookup, CVE query.
---

# Threat Intelligence Skill

This skill provides semantic search over cybersecurity's threat intelligence vector database,
covering MITRE ATT&CK, known malicious IPs, CVE records, and attacker TTPs.

## When to Use

- User wants to know if an IP is malicious
- User asks about a MITRE ATT&CK technique (e.g. T1078, T1090)
- User needs to check a file hash against known malware
- User asks about threat patterns, attack campaigns, or TTPs
- Any security alert analysis requiring background threat context

## Workflow

### Step 1 — Ensure vector DB is ingested
```bash
python scripts/ingest_threat_intel.py
```

If you see "0 chunks" output, the DB is empty. Always ingest before searching.

### Step 2 — Search threat intel
```bash
python skills/threat-intel-skill/scripts/search_intel.py "YOUR QUERY"
```

Examples:
```bash
python skills/threat-intel-skill/scripts/search_intel.py "Tor exit node 185.220.101.45"
python skills/threat-intel-skill/scripts/search_intel.py "T1078 valid accounts impossible travel"
python skills/threat-intel-skill/scripts/search_intel.py "ransomware WannaCry lateral movement"
```

### Step 3 — Hash lookup
```bash
python skills/threat-intel-skill/scripts/hash_lookup.py "HASH_VALUE"
```

Example:
```bash
python skills/threat-intel-skill/scripts/hash_lookup.py "5f4dcc3b5aa765d61d8327deb882cf99"
```

## Output Format

Search results return JSON with this structure:
```json
{
  "query": "the search query",
  "results": [
    {
      "text": "relevant threat intel chunk",
      "source": "mitre_attack | known_bad_ips | cve_samples",
      "distance": 0.12
    }
  ]
}
```

Hash lookup returns:
```json
{
  "hash": "...",
  "status": "MALICIOUS | NOT_FOUND",
  "malware_name": "WannaCry Dropper",
  "severity": "CRITICAL",
  "mitre": "T1486"
}
```

## Interpreting Results

- **distance < 0.3**: Strong match — highly relevant threat intel
- **distance 0.3–0.6**: Moderate match — useful context
- **distance > 0.6**: Weak match — treat with lower confidence
- **status: MALICIOUS**: Confirmed malware — always escalate to HIGH or CRITICAL severity
- **status: NOT_FOUND**: Hash not in local DB — recommend VirusTotal query in production

## Data Sources

| Source | Contents |
|--------|----------|
| `mitre_attack` | MITRE ATT&CK techniques, detection guidance, mitigations |
| `known_bad_ips` | Tor exit nodes, proxy IPs, botnet C2 infrastructure |
| `cve_samples` | CVE vulnerability records with severity scores |

## Adding New Threat Intel

Drop JSON files into `data/threat_intel/` and re-run ingestion:
```bash
python scripts/ingest_threat_intel.py --reset
```

Each JSON file should be a list of records. Each record will be chunked and embedded.
