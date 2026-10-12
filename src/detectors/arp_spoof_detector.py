"""
ARP Spoofing / Poisoning Detection Engine.
Detects:
1. Gateway MAC Address Flipping (Critical MITM indicator).
2. Conflicting IP-to-MAC associations (Duplicate IP / MAC hijacking).
3. Unsolicited ARP Replies (Gratuitous poisoning packets without matching requests).
4. High-frequency ARP reply storms (ARP Floods typical of ettercap/arpspoof).
"""
import time
from collections import defaultdict, deque
from typing import Dict, Any, Optional
from src.detectors.base_detector import BaseDetector, ThreatAlert

class ARPSpoofDetector(BaseDetector):
    def __init__(self, config: Dict[str, Any], network_state):
        super().__init__("ARP_Spoof_Detector", config, network_state)
        self.rate_limit_pps = config.get("rate_limit_pps", 5)
        self.unsolicited_reply_alert = config.get("unsolicited_reply_alert", True)
        self.gateway_mac_flip_alert = config.get("gateway_mac_flip_alert", True)

        # Sliding window for ARP reply rate tracking: IP -> deque of timestamps
        self.arp_reply_timestamps: Dict[str, deque] = defaultdict(lambda: deque(maxlen=20))
        # Sent ARP requests tracking: (target_ip, requested_ip) -> timestamp
        self.sent_arp_requests: Dict[str, float] = {}

    def analyze(self, packet: Dict[str, Any]) -> Optional[ThreatAlert]:
        if not self.enabled or packet.get("type") != "ARP":
            return None

        arp_op = packet.get("arp_op")
        src_ip = packet.get("src_ip")
        src_mac = packet.get("src_mac", "").lower()
        dst_ip = packet.get("dst_ip")
        dst_mac = packet.get("dst_mac", "").lower()
        now = time.time()

        # Track outgoing requests to correlate unsolicited replies
        if arp_op == "request":
            if src_ip == self.network_state.local_ip:
                self.sent_arp_requests[dst_ip] = now
            return None

        if arp_op == "reply":
            # 1. Check for Gateway MAC Flip (Highest Severity)
            if self.gateway_mac_flip_alert and self.network_state.gateway_ip:
                if src_ip == self.network_state.gateway_ip:
                    baseline_mac = self.network_state.baseline_gateway_mac
                    if baseline_mac and src_mac != baseline_mac:
                        return ThreatAlert(
                            threat_type="ARP_GATEWAY_POISONING",
                            severity="CRITICAL",
                            description=f"CRITICAL: Gateway {src_ip} MAC address changed from {baseline_mac} to {src_mac}! MITM attack in progress.",
                            attacker_ip=src_ip,
                            attacker_mac=src_mac,
                            victim_ip=self.network_state.local_ip,
                            victim_mac=self.network_state.local_mac,
                            evidence={
                                "gateway_ip": src_ip,
                                "baseline_mac": baseline_mac,
                                "forged_mac": src_mac,
                                "packet_op": arp_op
                            },
                            recommended_action="arp_pinning_and_firewall_block"
                        )

            # 2. Track ARP reply frequency (Flood / Storm Detection)
            timestamps = self.arp_reply_timestamps[src_ip]
            timestamps.append(now)
            # Check replies in the last 1 second
            recent_count = sum(1 for t in timestamps if now - t <= 1.0)
            if recent_count > self.rate_limit_pps:
                return ThreatAlert(
                    threat_type="ARP_REPLY_FLOOD",
                    severity="HIGH",
                    description=f"High rate ARP flood detected from IP {src_ip} (MAC: {src_mac}) at {recent_count} replies/sec.",
                    attacker_ip=src_ip,
                    attacker_mac=src_mac,
                    victim_ip=dst_ip,
                    victim_mac=dst_mac,
                    evidence={
                        "replies_per_second": recent_count,
                        "threshold": self.rate_limit_pps
                    },
                    recommended_action="rate_limit_and_isolate"
                )

            # 3. Check for IP-to-MAC conflict in network state history
            is_conflict = self.network_state.record_ip_mac(src_ip, src_mac)
            if is_conflict:
                known_macs = list(self.network_state.ip_mac_history.get(src_ip, set()))
                return ThreatAlert(
                    threat_type="ARP_CACHE_POISONING_CONFLICT",
                    severity="HIGH",
                    description=f"ARP Cache Poisoning: IP {src_ip} claimed by multiple MAC addresses: {known_macs}.",
                    attacker_ip=src_ip,
                    attacker_mac=src_mac,
                    victim_ip=dst_ip,
                    victim_mac=dst_mac,
                    evidence={
                        "ip": src_ip,
                        "conflicting_mac": src_mac,
                        "known_macs": known_macs
                    },
                    recommended_action="isolate_attacker"
                )

            # 4. Check for Unsolicited ARP Reply
            if self.unsolicited_reply_alert and dst_ip == self.network_state.local_ip:
                request_time = self.sent_arp_requests.pop(src_ip, None)
                # If no request was recorded or request was sent > 5 seconds ago
                if request_time is None or (now - request_time) > 5.0:
                    return ThreatAlert(
                        threat_type="UNSOLICITED_ARP_REPLY",
                        severity="MEDIUM",
                        description=f"Unsolicited ARP reply received for {src_ip} -> {src_mac} without prior request.",
                        attacker_ip=src_ip,
                        attacker_mac=src_mac,
                        victim_ip=dst_ip,
                        victim_mac=dst_mac,
                        evidence={
                            "claimed_ip": src_ip,
                            "claimed_mac": src_mac,
                            "solicited": False
                        },
                        recommended_action="inspect_and_pin"
                    )

        return None
