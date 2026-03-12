#!/usr/bin/env python3
"""
skills/threat-intel-skill/scripts/hash_lookup.py

Checks a file hash against the cybersecurity malware signature database.
In production this would call VirusTotal or Microsoft Defender ATP.

Usage:
    python skills/threat-intel-skill/scripts/hash_lookup.py "HASH"
    python skills/threat-intel-skill/scripts/hash_lookup.py "5f4dcc3b5aa765d61d8327deb882cf99"
"""

import sys
import json
import argparse

KNOWN_MALWARE = {
    "d41d8cd98f00b204e9800998ecf8427e": {
        "name": "Mimikatz", "category": "credential_stealer",
        "severity": "CRITICAL", "mitre": "T1003",
        "description": "Password dumping tool used extensively in APT campaigns and ransomware pre-staging."
    },
    "5f4dcc3b5aa765d61d8327deb882cf99": {
        "name": "WannaCry Dropper", "category": "ransomware",
        "severity": "CRITICAL", "mitre": "T1486",
        "description": "WannaCry ransomware dropper. Exploits EternalBlue (MS17-010). Self-propagating."
    },
    "abc123def456789012345678901234ab": {
        "name": "Cobalt Strike Beacon", "category": "c2_agent",
        "severity": "HIGH", "mitre": "T1071",
        "description": "Commercial red team tool widely abused by threat actors for C2 communication."
    },
    "098f6bcd4621d373cade4e832627b4f6": {
        "name": "Generic Adware", "category": "adware",
        "severity": "LOW", "mitre": "T1176",
        "description": "Low-risk adware. Unwanted but not immediately dangerous."
    },
}


def main():
    parser = argparse.ArgumentParser(description="Check file hash against malware DB")
    parser.add_argument("hash", help="MD5, SHA1, or SHA256 hash to look up")
    args = parser.parse_args()

    normalized = args.hash.lower().strip()
    hit = KNOWN_MALWARE.get(normalized)

    if hit:
        result = {
            "hash": args.hash,
            "status": "MALICIOUS",
            "malware_name": hit["name"],
            "category": hit["category"],
            "severity": hit["severity"],
            "mitre_technique": hit["mitre"],
            "description": hit["description"],
            "recommended_action": "ISOLATE endpoint immediately and begin incident response."
        }
    else:
        result = {
            "hash": args.hash,
            "status": "NOT_FOUND",
            "note": "Hash not in local DB. Query VirusTotal or Microsoft Defender ATP for production use.",
            "recommended_action": "Submit to VirusTotal for community analysis."
        }

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
