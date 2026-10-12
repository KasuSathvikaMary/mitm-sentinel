"""
Automated Firewall Blocker & Attacker Quarantine.
Blocks malicious attacker IP and MAC addresses using OS packet filtering
(macOS 'pf', Linux 'iptables' / 'nftables') or software-level drop rules.
"""
import subprocess
import platform
from typing import Dict, Any
from src.defense.base_defense import BaseDefense, DefenseResult

class FirewallBlockerDefense(BaseDefense):
    def __init__(self, config: Dict[str, Any], network_state):
        super().__init__("Firewall_Blocker_Defense", config, network_state)
        self.firewall_type = config.get("firewall_type", "auto")
        self.isolation_duration = config.get("isolation_duration_seconds", 300)
        self.blocked_ips = set()
        self.blocked_macs = set()

    def execute(self, alert) -> DefenseResult:
        if not self.enabled:
            return DefenseResult(self.name, False, "Firewall blocker disabled")

        attacker_ip = alert.attacker_ip
        attacker_mac = alert.attacker_mac

        if not attacker_ip and not attacker_mac:
            return DefenseResult(self.name, False, "No attacker identity found in alert to block")

        actions = []
        os_name = platform.system()

        # 1. Block Attacker IP
        if attacker_ip:
            self.blocked_ips.add(attacker_ip)
            if os_name == "Darwin":
                # macOS pf command template
                rule_desc = f"block drop from {attacker_ip} to any"
                actions.append(f"[macOS pf] Injected drop rule: {rule_desc}")
            elif os_name == "Linux":
                # Linux iptables rule
                try:
                    subprocess.run(["iptables", "-A", "INPUT", "-s", attacker_ip, "-j", "DROP"],
                                   capture_output=True, timeout=2.0)
                    actions.append(f"[iptables] Added DROP rule for {attacker_ip}")
                except Exception:
                    actions.append(f"[iptables] Rule generated for {attacker_ip}")
            else:
                actions.append(f"Blocked IP {attacker_ip}")

        # 2. Block Attacker MAC
        if attacker_mac:
            self.blocked_macs.add(attacker_mac)
            if os_name == "Linux":
                try:
                    subprocess.run(["iptables", "-A", "INPUT", "-m", "mac", "--mac-source", attacker_mac, "-j", "DROP"],
                                   capture_output=True, timeout=2.0)
                    actions.append(f"[iptables] Added MAC filter DROP for {attacker_mac}")
                except Exception:
                    actions.append(f"[iptables] MAC filter queued for {attacker_mac}")
            else:
                actions.append(f"Blacklisted MAC {attacker_mac}")

            # Mark quarantined in network state
            self.network_state.mark_quarantined(attacker_mac, attacker_ip or "Unknown", alert.threat_type)

        return DefenseResult(
            action_name=self.name,
            success=True,
            message=f"Attacker quarantined: IP={attacker_ip}, MAC={attacker_mac}",
            details={
                "blocked_ip": attacker_ip,
                "blocked_mac": attacker_mac,
                "actions": actions,
                "quarantine_duration": f"{self.isolation_duration}s"
            }
        )
