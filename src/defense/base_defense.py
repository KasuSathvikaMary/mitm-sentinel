"""
Base Defense interface for automated MITM countermeasures.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from datetime import datetime, timezone

class DefenseResult:
    def __init__(self, action_name: str, success: bool, message: str, details: Optional[Dict[str, Any]] = None):
        self.action_name = action_name
        self.success = success
        self.message = message
        self.details = details or {}
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_name": self.action_name,
            "success": self.success,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp
        }

class BaseDefense(ABC):
    def __init__(self, name: str, config: Dict[str, Any], network_state):
        self.name = name
        self.config = config
        self.network_state = network_state
        self.enabled = config.get("enabled", True)

    @abstractmethod
    def execute(self, alert) -> DefenseResult:
        """Executes countermeasure based on the threat alert."""
        pass
