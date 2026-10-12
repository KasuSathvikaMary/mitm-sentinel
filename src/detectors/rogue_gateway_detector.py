"""
Rogue Gateway & ICMP Redirect Detector.
Detects:
1. ICMP Redirect messages (Type 5) attempting to redirect routing paths through an attacker host.
2. Rogue DHCP Offer / ACK packets pushing unauthorized default gateways.
"""
from typing import Dict, Any, Optional
from src.detectors.base_detector import BaseDetector, ThreatAlert

class RogueGatewayDetector(BaseDetector):
    def __init__(self, config: Dict[str, Any], network_state):
        super().__init__("Rogue_Gateway_Detector", config, network_state)
        self.detect_icmp_redirect = config.get("detect_icmp_redirect", True)
        self.detect_rogue_dhcp = config.get("detect_rogue_dhcp", True)

    def analyze(self, packet: Dict[str, Any]) -> Optional[ThreatAlert]:
        if not self.enabled:
            return None

        pkt_type = packet.get("type")

        # 1. ICMP Redirect Detection (Type 5)
        if pkt_type == "ICMP" and self.detect_icmp_redirect:
            icmp_type = packet.get("icmp_type")
            if icmp_type == 5: # ICMP Redirect
                src_ip = packet.get("src_ip")
                redirect_gw = packet.get("redirect_gateway_ip")
                return ThreatAlert(
                    threat_type="ICMP_REDIRECT_ATTACK",
                    severity="HIGH",
                    description=f"ICMP Redirect from {src_ip}: Attempting to redirect routing to gateway {redirect_gw}.",
                    attacker_ip=src_ip,
                    victim_ip=packet.get("dst_ip"),
                    evidence={
                        "source": src_ip,
                        "suggested_gateway": redirect_gw
                    },
                    recommended_action="drop_icmp_redirects_and_block_source"
                )

        # 2. Rogue DHCP Detection
        if pkt_type == "DHCP" and self.detect_rogue_dhcp:
            dhcp_type = packet.get("dhcp_message_type")
            offered_router = packet.get("offered_router")
            server_ip = packet.get("src_ip")

            if dhcp_type in ["OFFER", "ACK"] and offered_router:
                # If router offered does not match known baseline gateway
                if self.network_state.gateway_ip and offered_router != self.network_state.gateway_ip:
                    return ThreatAlert(
                        threat_type="ROGUE_DHCP_GATEWAY_HIJACK",
                        severity="CRITICAL",
                        description=f"Rogue DHCP Server {server_ip} offering unauthorized gateway {offered_router} (Expected: {self.network_state.gateway_ip}).",
                        attacker_ip=server_ip,
                        attacker_mac=packet.get("src_mac"),
                        victim_ip=packet.get("dst_ip"),
                        evidence={
                            "dhcp_server": server_ip,
                            "offered_gateway": offered_router,
                            "legitimate_gateway": self.network_state.gateway_ip
                        },
                        recommended_action="isolate_rogue_dhcp_server"
                    )

        return None
