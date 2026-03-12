"""
agent/parser.py — Alert normalization and validation.

Converts raw alert dicts into typed AlertModel objects.
Raises ValueError for invalid or injection-containing alerts.
"""

from __future__ import annotations
from enum import Enum
from typing import Optional

from pydantic import BaseModel, field_validator


class AlertType(str, Enum):
    suspicious_login     = "suspicious_login"
    malware_detected     = "malware_detected"
    data_exfiltration    = "data_exfiltration"
    privilege_escalation = "privilege_escalation"
    lateral_movement     = "lateral_movement"
    network_anomaly      = "network_anomaly"
    unknown              = "unknown"


class AlertModel(BaseModel):
    alert_id:        str
    alert_type:      AlertType
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
    raw_description: Optional[str]   = None
    timestamp:       Optional[str]   = None

    @field_validator("alert_id")
    @classmethod
    def alert_id_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("alert_id must not be empty")
        return v.strip()


def parse_alert(raw: dict) -> AlertModel:
    """
    Normalize a raw alert dict into an AlertModel.
    Maps the 'type' key to AlertType enum; unknown types become AlertType.unknown.
    Raises ValueError if required fields are missing.
    """
    if not raw.get("alert_id"):
        raise ValueError("Alert must have an 'alert_id'")

    type_str = raw.get("type", "unknown")
    try:
        alert_type = AlertType(type_str)
    except ValueError:
        alert_type = AlertType.unknown

    return AlertModel(
        alert_id        = str(raw["alert_id"]),
        alert_type      = alert_type,
        user            = raw.get("user"),
        source_ip       = raw.get("source_ip"),
        destination_ip  = raw.get("destination_ip"),
        hostname        = raw.get("hostname"),
        location        = raw.get("location"),
        prev_location   = raw.get("prev_location"),
        time_gap_hours  = raw.get("time_gap_hours"),
        failed_attempts = raw.get("failed_attempts"),
        file_hash       = raw.get("file_hash"),
        process_name    = raw.get("process_name"),
        raw_description = raw.get("description"),
        timestamp       = raw.get("timestamp"),
    )
