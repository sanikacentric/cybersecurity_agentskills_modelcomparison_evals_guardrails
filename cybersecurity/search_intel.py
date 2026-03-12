#!/usr/bin/env python3
"""
skills/threat-intel-skill/scripts/search_intel.py

Standalone script executed by the Threat Intel Skill.
Performs semantic search over the ChromaDB vector store.

Usage:
    python skills/threat-intel-skill/scripts/search_intel.py "query string"
    python skills/threat-intel-skill/scripts/search_intel.py "T1078" --top-k 3
    python skills/threat-intel-skill/scripts/search_intel.py "185.220.101.45" --format json
"""

import sys
import json
import argparse
from pathlib import Path

# Make project root importable
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from agent.retriever import get_retriever


def main():
    parser = argparse.ArgumentParser(description="Search cybersecurity threat intelligence")
    parser.add_argument("query", help="Search query: IP, hash, technique ID, or natural language")
    parser.add_argument("--top-k", type=int, default=5, help="Number of results (default: 5)")
    parser.add_argument("--format", choices=["json", "text"], default="json", help="Output format")
    args = parser.parse_args()

    retriever = get_retriever()

    if retriever._collection.count() == 0:
        result = {
            "error": "Vector DB is empty. Run: python scripts/ingest_threat_intel.py",
            "query": args.query,
            "results": []
        }
        print(json.dumps(result, indent=2))
        sys.exit(1)

    results = retriever.query(args.query, k=args.top_k)

    if args.format == "json":
        output = {
            "query": args.query,
            "total_results": len(results),
            "results": results
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"\n[>>] Threat Intel Search: '{args.query}'")
        print(f"{'='*60}")
        if not results:
            print("No results found.")
        for i, r in enumerate(results, 1):
            print(f"\n[{i}] Source: {r['source']} | Distance: {r['distance']}")
            print("-" * 40)
            print(r["text"][:400])


if __name__ == "__main__":
    main()
