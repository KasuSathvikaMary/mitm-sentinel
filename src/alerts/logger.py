"""
Structured JSON Security Event Logger.
"""
import os
import json
from datetime import datetime, timezone
from typing import Dict, Any

class SecurityLogger:
    def __init__(self, log_path: str = "logs/mitm_events.json"):
        self.log_path = log_path
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

    def log_event(self, event_type: str, data: Dict[str, Any]):
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "data": data
        }
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception as e:
            print(f"[Logger Error] Failed to write to {self.log_path}: {e}")
