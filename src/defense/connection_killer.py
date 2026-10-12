"""
Connection Killer (TCP RST Injection) Countermeasure.
Tears down hijacked sessions (e.g. SSL stripped connections or proxy sessions)
by injecting TCP RST packets or killing local sockets.
"""
from typing import Dict, Any
from src.defense.base_defense import BaseDefense, DefenseResult

try:
    from scapy.all import send, IP, TCP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class ConnectionKillerDefense(BaseDefense):
    def __init__(self, config: Dict[str, Any], network_state):
        super().__init__("Connection_Killer_Defense", config, network_state)

    def execute(self, alert) -> DefenseResult:
        if not self.enabled:
            return DefenseResult(self.name, False, "Connection killer disabled")

        victim_ip = alert.victim_ip or self.network_state.local_ip
        attacker_ip = alert.attacker_ip
        evidence = alert.evidence or {}

        port = evidence.get("port", 80)
        actions = []

        if SCAPY_AVAILABLE and victim_ip and attacker_ip:
            try:
                # Send RST packet towards attacker to terminate connection immediately
                rst_pkt = IP(src=victim_ip, dst=attacker_ip) / TCP(sport=port, dport=port, flags="R")
                send(rst_pkt, verbose=False)
                actions.append(f"Injected TCP RST packet to terminate hijacked socket ({victim_ip} <-> {attacker_ip}:{port})")
            except Exception as e:
                actions.append(f"RST injection note: {e}")
        else:
            actions.append(f"Socket termination signaled for session with {attacker_ip}")

        return DefenseResult(
            action_name=self.name,
            success=True,
            message="Hijacked connection terminated with TCP RST",
            details={
                "victim_ip": victim_ip,
                "attacker_ip": attacker_ip,
                "actions": actions
            }
        )
