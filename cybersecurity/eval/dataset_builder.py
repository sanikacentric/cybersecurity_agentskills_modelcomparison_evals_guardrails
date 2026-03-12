"""
eval/dataset_builder.py — Synthetic labeled alert dataset generator.

Generates 100 realistic security alerts with ground-truth severity labels
for use in the evaluation framework.

Usage:
    python -m eval.dataset_builder
    python -m eval.dataset_builder --count 50 --output data/synthetic_alerts/test_dataset.json
"""

from __future__ import annotations
import json
import random
import argparse
from pathlib import Path
from datetime import datetime, timedelta

from config import EVAL_DATASET_PATH

random.seed(42)

# ── Alert templates ────────────────────────────────────────────────────────────
ALERT_TEMPLATES = [
    # suspicious_login — HIGH/CRITICAL
    {
        "type": "suspicious_login", "severity": "HIGH",
        "user": "john.doe@company.com", "source_ip": "185.220.101.45",
        "location": "Romania", "prev_location": "New York, USA",
        "time_gap_hours": 2.0, "failed_attempts": 0,
    },
    {
        "type": "suspicious_login", "severity": "CRITICAL",
        "user": "admin@company.com", "source_ip": "203.0.113.45",
        "location": "Beijing", "prev_location": "San Francisco",
        "time_gap_hours": 1.0, "failed_attempts": 5,
    },
    # suspicious_login — MEDIUM
    {
        "type": "suspicious_login", "severity": "MEDIUM",
        "user": "jane.smith@company.com", "source_ip": "198.51.100.22",
        "location": "Paris", "prev_location": "London, UK",
        "time_gap_hours": 3.0, "failed_attempts": 1,
    },
    # suspicious_login — LOW
    {
        "type": "suspicious_login", "severity": "LOW",
        "user": "alice@company.com", "source_ip": "192.168.1.100",
        "location": "New York, USA", "prev_location": "Boston, USA",
        "time_gap_hours": 5.0, "failed_attempts": 0,
    },
    # malware_detected — CRITICAL
    {
        "type": "malware_detected", "severity": "CRITICAL",
        "hostname": "WORKSTATION-42", "file_hash": "5f4dcc3b5aa765d61d8327deb882cf99",
        "process_name": "svchost.exe",
        "description": "Suspicious process spawned from user temp directory",
    },
    {
        "type": "malware_detected", "severity": "CRITICAL",
        "hostname": "SERVER-01", "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
        "process_name": "lsass.exe",
        "description": "Credential dumping activity detected",
    },
    # malware_detected — HIGH
    {
        "type": "malware_detected", "severity": "HIGH",
        "hostname": "LAPTOP-99", "file_hash": "abc123def456789012345678901234ab",
        "process_name": "beacon.exe",
        "description": "Unknown executable communicating with external IP",
    },
    # malware_detected — LOW
    {
        "type": "malware_detected", "severity": "LOW",
        "hostname": "WORKSTATION-10", "file_hash": "098f6bcd4621d373cade4e832627b4f6",
        "process_name": "adware_toolbar.exe",
        "description": "PUP detected during scheduled scan",
    },
    # data_exfiltration — HIGH
    {
        "type": "data_exfiltration", "severity": "HIGH",
        "user": "contractor@external.com", "source_ip": "10.0.0.50",
        "destination_ip": "203.0.113.45",
        "description": "Large data transfer to external IP outside business hours (2.4GB)",
    },
    # network_anomaly — MEDIUM
    {
        "type": "network_anomaly", "severity": "MEDIUM",
        "source_ip": "192.168.1.50", "destination_ip": "185.220.101.45",
        "description": "Unusual outbound traffic spike to known Tor exit node",
    },
    # privilege_escalation — HIGH
    {
        "type": "privilege_escalation", "severity": "HIGH",
        "user": "svc_account@company.com", "hostname": "DC-01",
        "description": "Service account added to Domain Admins group",
    },
    # lateral_movement — HIGH
    {
        "type": "lateral_movement", "severity": "HIGH",
        "source_ip": "192.168.1.100", "destination_ip": "192.168.1.5",
        "description": "SMB scanning from workstation to multiple internal servers",
    },
    # LOW alerts
    {
        "type": "suspicious_login", "severity": "LOW",
        "user": "bob@company.com", "source_ip": "192.168.1.10",
        "location": "New York, USA", "prev_location": "New York, USA",
        "time_gap_hours": 8.0, "failed_attempts": 0,
    },
    {
        "type": "network_anomaly", "severity": "LOW",
        "source_ip": "192.168.1.100",
        "description": "Minor DNS query spike — likely software update",
    },
]

SEVERITY_DISTRIBUTION = {
    "CRITICAL": 0.15,
    "HIGH":     0.30,
    "MEDIUM":   0.25,
    "LOW":      0.30,
}


def _random_timestamp(base: datetime, spread_hours: int = 72) -> str:
    offset = timedelta(hours=random.uniform(0, spread_hours))
    return (base - offset).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_dataset(count: int = 100) -> list[dict]:
    """Generate `count` synthetic alert records with ground-truth severity."""
    base_time = datetime(2024, 1, 15, 12, 0, 0)
    dataset   = []

    for i in range(count):
        template = random.choice(ALERT_TEMPLATES)
        alert    = dict(template)

        alert["alert_id"]  = f"EVAL-{i+1:04d}"
        alert["timestamp"] = _random_timestamp(base_time)

        # Slightly vary numeric fields to add diversity
        if "time_gap_hours" in alert:
            alert["time_gap_hours"] = round(
                alert["time_gap_hours"] * random.uniform(0.5, 2.0), 1
            )
        if "failed_attempts" in alert and alert["failed_attempts"] > 0:
            alert["failed_attempts"] = random.randint(1, 10)

        dataset.append({
            "alert":           {k: v for k, v in alert.items() if k != "severity"},
            "ground_truth":    alert["severity"],
        })

    return dataset


def save_dataset(dataset: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(dataset, f, indent=2)
    print(f"[OK] Dataset saved: {path} ({len(dataset)} alerts)")


def main():
    parser = argparse.ArgumentParser(description="Build synthetic eval dataset")
    parser.add_argument("--count",  type=int, default=100, help="Number of alerts")
    parser.add_argument("--output", type=str, default=str(EVAL_DATASET_PATH))
    args = parser.parse_args()

    dataset = build_dataset(args.count)
    save_dataset(dataset, Path(args.output))

    # Print distribution
    from collections import Counter
    dist = Counter(d["ground_truth"] for d in dataset)
    print("\nSeverity distribution:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        print(f"  {sev:<10}: {dist.get(sev, 0):>3} alerts")


if __name__ == "__main__":
    main()
