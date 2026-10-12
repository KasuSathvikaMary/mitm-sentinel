"""
Webhook notification dispatcher (Slack / Discord / SIEM).
"""
import requests
from typing import Dict, Any

class WebhookNotifier:
    def __init__(self, url: str, enabled: bool = False):
        self.url = url
        self.enabled = enabled and bool(url)

    def send_alert(self, alert_data: Dict[str, Any]):
        if not self.enabled or not self.url:
            return

        payload = {
            "text": f"🚨 *[MITM SENTINEL ALERT]* {alert_data.get('threat_type')}\n"
                    f"*Severity:* {alert_data.get('severity')}\n"
                    f"*Description:* {alert_data.get('description')}\n"
                    f"*Attacker:* {alert_data.get('attacker_ip')} ({alert_data.get('attacker_mac')})"
        }
        try:
            requests.post(self.url, json=payload, timeout=3.0)
        except Exception:
            pass
