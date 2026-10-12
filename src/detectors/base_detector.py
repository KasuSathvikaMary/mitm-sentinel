"""
Base Detector interface for MITM attack detection modules.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from datetime import datetime, timezone

class ThreatAlert:
    def __init__(
        self,
        threat_type: str,
        severity: str, # "LOW", "MEDIUM", "HIGH", "CRITICAL"
        description: str,
        attacker_ip: Optional[str] = None,
        attacker_mac: Optional[str] = None,
        victim_ip: Optional[str] = None,
        victim_mac: Optional[str] = None,
        evidence: Optional[Dict[str, Any]] = None,
        recommended_action: Optional[str] = None
    ):
        self.threat_type = threat_type
        self.severity = severity
        self.description = description
        self.attacker_ip = attacker_ip
        self.attacker_mac = attacker_mac
        self.victim_ip = victim_ip
        self.victim_mac = victim_mac
        self.evidence = evidence or {}
        self.recommended_action = recommended_action or "quarantine"
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "threat_type": self.threat_type,
            "severity": self.severity,
            "description": self.description,
            "attacker_ip": self.attacker_ip,
            "attacker_mac": self.attacker_mac,
            "victim_ip": self.victim_ip,
            "victim_mac": self.victim_mac,
            "evidence": self.evidence,
            "recommended_action": self.recommended_action,
            "timestamp": self.timestamp
        }

class BaseDetector(ABC):
    def __init__(self, name: str, config: Dict[str, Any], network_state):
        self.name = name
        self.config = config
        self.network_state = network_state
        self.enabled = config.get("enabled", True)

    @abstractmethod
    def analyze(self, packet: Dict[str, Any]) -> Optional[ThreatAlert]:
        """Analyzes a normalized packet. Returns ThreatAlert if an attack is detected."""
        pass
