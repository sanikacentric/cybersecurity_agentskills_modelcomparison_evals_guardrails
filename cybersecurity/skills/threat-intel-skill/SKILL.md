---
name: threat-intel-skill
description: >
  Search and retrieve cybersecurity threat intelligence from the cybersecurity
  vector database. Use this skill when analyzing security alerts, looking up malicious
  IPs, checking file hashes against known malware, querying MITRE ATT&CK techniques,
  or retrieving CVE vulnerability data.
triggers:
  - IP reputation lookup
  - hash check
  - threat intel search
  - MITRE technique lookup
  - CVE query
  - malware lookup
  - is this IP malicious
  - what is T1078
  - check this hash
---

# Threat Intelligence Skill

Provides semantic search over cybersecurity's live threat intelligence vector
database (ChromaDB) covering MITRE ATT&CK techniques, known malicious IPs,
CVE records, and attacker TTPs.

## When to Use

- User wants to know if an IP is malicious or associated with known threat actors
- User asks about a MITRE ATT&CK technique (e.g. T1078, T1090, T1486)
- User needs to check a file hash against known malware signatures
- User asks about threat patterns, attack campaigns, or TTPs
- Any security alert analysis requiring background threat context

## Scripts in This Skill

| Script | Purpose |
|--------|---------|
| `scripts/search_intel.py` | Semantic vector search over ChromaDB threat intel DB |
| `scripts/hash_lookup.py` | Lookup file hash against known malware signature database |

---

## Usage

### Step 1 — Ensure vector DB is populated

```bash
python scripts/ingest_threat_intel.py
```

Run this once before first use. Use `--force` to re-ingest updated threat intel.

### Step 2 — Search threat intelligence

```bash
python skills/threat-intel-skill/scripts/search_intel.py "YOUR QUERY"
python skills/threat-intel-skill/scripts/search_intel.py "YOUR QUERY" --top-k 3
python skills/threat-intel-skill/scripts/search_intel.py "YOUR QUERY" --format text
```

Examples:
```bash
python skills/threat-intel-skill/scripts/search_intel.py "Tor exit node 185.220.101.45"
python skills/threat-intel-skill/scripts/search_intel.py "T1078 valid accounts credential stuffing"
python skills/threat-intel-skill/scripts/search_intel.py "WannaCry ransomware EternalBlue lateral movement"
python skills/threat-intel-skill/scripts/search_intel.py "CVE-2021-44228 Log4Shell"
```

### Step 3 — Hash lookup

```bash
python skills/threat-intel-skill/scripts/hash_lookup.py "HASH_VALUE"
```

Examples:
```bash
python skills/threat-intel-skill/scripts/hash_lookup.py "5f4dcc3b5aa765d61d8327deb882cf99"
python skills/threat-intel-skill/scripts/hash_lookup.py "d41d8cd98f00b204e9800998ecf8427e"
python skills/threat-intel-skill/scripts/hash_lookup.py "abc123def456789012345678901234ab"
```

---

## Output Format

### search_intel.py output (JSON)

```json
{
  "query": "Tor exit node suspicious login",
  "total_results": 3,
  "results": [
    {
      "text": "185.220.101.45 — Known Tor exit node. Frequently used to anonymize credential stuffing attacks...",
      "source": "malicious_ips.txt",
      "distance": 0.11
    },
    {
      "text": "T1090 - Proxy (Tor). Adversaries use Tor to disguise the origin of attacks...",
      "source": "mitre_attack.txt",
      "distance": 0.23
    }
  ]
}
```

### hash_lookup.py output (JSON)

```json
{
  "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
  "status": "MALICIOUS",
  "malware_name": "WannaCry Dropper",
  "category": "ransomware",
  "severity": "CRITICAL",
  "mitre_technique": "T1486",
  "description": "WannaCry ransomware dropper. Exploits EternalBlue (MS17-010). Self-propagating.",
  "recommended_action": "ISOLATE endpoint immediately and begin incident response."
}
```

---

## Interpreting Results

| Condition | Meaning |
|-----------|---------|
| `distance < 0.3` | Strong match — highly relevant threat intel |
| `distance 0.3–0.6` | Moderate match — useful supporting context |
| `distance > 0.6` | Weak match — treat with lower confidence |
| `status: MALICIOUS` | Confirmed malware — escalate to HIGH or CRITICAL |
| `status: NOT_FOUND` | Not in local DB — query VirusTotal in production |

---

## Data Sources

| Source File | Contents |
|-------------|----------|
| `data/threat_intel/mitre_attack.txt` | MITRE ATT&CK techniques T1003, T1021, T1041, T1071, T1078, T1090, T1110, T1486, T1548 |
| `data/threat_intel/malicious_ips.txt` | Tor exit nodes, APT41 C2 servers, scanning infrastructure |
| `data/threat_intel/cves.txt` | EternalBlue, ProxyLogon, Log4Shell, Follina, Confluence OGNL, Outlook NTLM |

---

## Adding New Threat Intel

Drop `.txt` files into `data/threat_intel/` and re-run ingestion:

```bash
python scripts/ingest_threat_intel.py --force
```
