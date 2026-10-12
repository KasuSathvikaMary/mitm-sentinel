"""
Alert Manager: Orchestrates alert dispatch across console, desktop notifications,
JSON audit logging, webhooks, and event bus pub/sub.
"""
from typing import Dict, Any, List
from src.alerts.desktop_notifier import DesktopNotifier
from src.alerts.logger import SecurityLogger
from src.alerts.webhook_notifier import WebhookNotifier

class AlertManager:
    def __init__(self, config: Dict[str, Any], event_bus):
        self.config = config
        self.event_bus = event_bus

        alert_cfg = config.get("alerting", {})
        self.desktop_notifier = DesktopNotifier(enabled=alert_cfg.get("desktop_notifications", True))
        self.logger = SecurityLogger(log_path=config.get("system", {}).get("event_log_path", "logs/mitm_events.json"))
        webhook_cfg = alert_cfg.get("webhook", {})
        self.webhook_notifier = WebhookNotifier(url=webhook_cfg.get("url", ""), enabled=webhook_cfg.get("enabled", False))

        self.alerts_history: List[Dict[str, Any]] = []

    def dispatch(self, alert):
        alert_dict = alert.to_dict()
        self.alerts_history.append(alert_dict)
        if len(self.alerts_history) > 200:
            self.alerts_history.pop(0)

        # 1. Log to structured security audit trail
        self.logger.log_event("THREAT_ALERT", alert_dict)

        # 2. Desktop notification
        self.desktop_notifier.notify(
            title=f"MITM Alert: {alert.threat_type}",
            message=alert.description[:120],
            severity=alert.severity
        )

        # 3. Webhook (Slack / Discord)
        self.webhook_notifier.send_alert(alert_dict)

        # 4. Broadcast on EventBus for WebSocket & UI consumers
        self.event_bus.publish("ALERT", alert_dict)
