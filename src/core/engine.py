"""
Central MITM Sentinel Engine.
Coordinates packet capture, detection pipeline, automated defense countermeasures,
state tracking, and alerting.
"""
import yaml
import os
import threading
from typing import Dict, Any, Optional, List

from src.core.event_bus import EventBus
from src.core.network_state import NetworkState
from src.core.packet_capture import PacketCapture
from src.detectors import (
    BaseDetector,
    ThreatAlert,
    ARPSpoofDetector,
    DNSSpoofDetector,
    SSLTamperDetector,
    RogueGatewayDetector
)
from src.defense import (
    BaseDefense,
    DefenseResult,
    ARPImmunityDefense,
    FirewallBlockerDefense,
    DNSSecEnforcerDefense,
    ConnectionKillerDefense
)
from src.alerts.alert_manager import AlertManager

class MITMSentinelEngine:
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.event_bus = EventBus()
        self.network_state = NetworkState(interface=self.config.get("system", {}).get("interface"))
        self.alert_manager = AlertManager(self.config, self.event_bus)

        # Initialize Detectors
        det_cfg = self.config.get("detection", {})
        self.detectors: List[BaseDetector] = [
            ARPSpoofDetector(det_cfg.get("arp_spoofing", {}), self.network_state),
            DNSSpoofDetector(det_cfg.get("dns_spoofing", {}), self.network_state),
            SSLTamperDetector(det_cfg.get("ssl_tampering", {}), self.network_state),
            RogueGatewayDetector(det_cfg.get("rogue_gateway", {}), self.network_state)
        ]

        # Initialize Defense Countermeasures
        def_cfg = self.config.get("defense", {})
        self.defenses: Dict[str, BaseDefense] = {
            "arp_pinning": ARPImmunityDefense(def_cfg.get("arp_pinning", {}), self.network_state),
            "firewall_block": FirewallBlockerDefense(def_cfg.get("attacker_isolation", {}), self.network_state),
            "dns_fallback": DNSSecEnforcerDefense(def_cfg.get("dns_fallback", {}), self.network_state),
            "connection_kill": ConnectionKillerDefense(def_cfg.get("connection_kill", {}), self.network_state)
        }

        self.auto_remediate = def_cfg.get("auto_remediate", True)
        self.packet_capture = PacketCapture(
            interface=self.network_state.interface,
            packet_callback=self.process_packet
        )

        self.is_running = False
        self._lock = threading.Lock()

    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        default_path = "config/config.yaml"
        target_path = config_path or default_path
        if os.path.exists(target_path):
            with open(target_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        return {
            "system": {"name": "MITM-Sentinel", "interface": "en0", "mode": "active"},
            "detection": {
                "arp_spoofing": {"enabled": True},
                "dns_spoofing": {"enabled": True},
                "ssl_tampering": {"enabled": True},
                "rogue_gateway": {"enabled": True}
            },
            "defense": {"auto_remediate": True},
            "alerting": {"desktop_notifications": True}
        }

    def process_packet(self, packet: Dict[str, Any]):
        """Pipeline callback: processes an incoming packet through detectors."""
        with self._lock:
            self.network_state.metrics["packets_analyzed"] += 1
            pkt_type = packet.get("type")
            if pkt_type == "ARP":
                self.network_state.metrics["arp_packets"] += 1
            elif pkt_type == "DNS":
                self.network_state.metrics["dns_packets"] += 1
            elif pkt_type in ["TLS", "HTTP"]:
                self.network_state.metrics["tls_packets"] += 1

        # Broadcast packet event for UI inspector
        self.event_bus.publish("PACKET", packet)

        # Run through active detectors
        for detector in self.detectors:
            try:
                alert = detector.analyze(packet)
                if alert:
                    self._handle_threat(alert)
            except Exception as e:
                print(f"[Engine] Detector {detector.name} error: {e}")

    def _handle_threat(self, alert: ThreatAlert):
        """Called when a detector identifies a threat."""
        with self._lock:
            self.network_state.metrics["attacks_detected"] += 1

        # 1. Dispatch Alert (desktop notification, log, webhook, UI)
        self.alert_manager.dispatch(alert)

        # 2. Trigger Defensive Countermeasures if auto_remediate enabled
        if self.auto_remediate:
            self.execute_defense_for_alert(alert)

    def execute_defense_for_alert(self, alert: ThreatAlert) -> List[DefenseResult]:
        """Maps threat to appropriate defensive actions and executes them."""
        results = []
        action_type = alert.recommended_action or ""

        # ARP attacks -> ARP Pinning & Attacker Isolation
        if "arp" in action_type or "ARP" in alert.threat_type:
            arp_def = self.defenses.get("arp_pinning")
            if arp_def:
                res = arp_def.execute(alert)
                results.append(res)
                self.event_bus.publish("DEFENSE", res.to_dict())

            fw_def = self.defenses.get("firewall_block")
            if fw_def and alert.attacker_mac:
                res = fw_def.execute(alert)
                results.append(res)
                self.event_bus.publish("DEFENSE", res.to_dict())

        # DNS attacks -> Fallback DoH & Flush cache
        elif "dns" in action_type.lower() or "DNS" in alert.threat_type:
            dns_def = self.defenses.get("dns_fallback")
            if dns_def:
                res = dns_def.execute(alert)
                results.append(res)
                self.event_bus.publish("DEFENSE", res.to_dict())

        # SSL attacks / Stripping -> TCP RST Connection Kill & Firewall Isolation
        elif "ssl" in action_type.lower() or "SSL" in alert.threat_type or "PROXY" in alert.threat_type:
            kill_def = self.defenses.get("connection_kill")
            if kill_def:
                res = kill_def.execute(alert)
                results.append(res)
                self.event_bus.publish("DEFENSE", res.to_dict())

            fw_def = self.defenses.get("firewall_block")
            if fw_def and alert.attacker_ip:
                res = fw_def.execute(alert)
                results.append(res)
                self.event_bus.publish("DEFENSE", res.to_dict())

        # General quarantine
        else:
            fw_def = self.defenses.get("firewall_block")
            if fw_def:
                res = fw_def.execute(alert)
                results.append(res)
                self.event_bus.publish("DEFENSE", res.to_dict())

        with self._lock:
            self.network_state.metrics["defenses_triggered"] += len(results)

        return results

    def start_live_capture(self):
        """Starts real-time live sniffing."""
        self.is_running = True
        self.packet_capture.start_live()

    def stop(self):
        """Stops engine and packet capture."""
        self.is_running = False
        self.packet_capture.stop()
