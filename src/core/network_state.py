"""
Network state manager: tracks gateway, ARP cache baseline, local interface details,
active threats, quarantined attackers, and real-time telemetry metrics.
"""
import subprocess
import socket
import re
import sys
import platform
from typing import Dict, Optional, Set, Any
from datetime import datetime, timezone

class NetworkState:
    def __init__(self, interface: Optional[str] = None):
        self.interface = interface or self._detect_default_interface()
        self.local_ip: Optional[str] = None
        self.local_mac: Optional[str] = None
        self.gateway_ip: Optional[str] = None
        self.gateway_mac: Optional[str] = None
        self.baseline_gateway_mac: Optional[str] = None

        # Dynamic IP -> MAC mapping table
        self.arp_table: Dict[str, str] = {}
        # Historical mapping: IP -> set of observed MAC addresses
        self.ip_mac_history: Dict[str, Set[str]] = {}

        # Pending DNS queries: Transaction ID -> {domain, query_time, client_ip}
        self.pending_dns_queries: Dict[int, Dict[str, Any]] = {}

        # Known attackers: MAC -> {ip, threat_type, detected_at, quarantined}
        self.quarantined_attackers: Dict[str, Dict[str, Any]] = {}

        # Real-time telemetry counters
        self.metrics = {
            "packets_analyzed": 0,
            "arp_packets": 0,
            "dns_packets": 0,
            "tls_packets": 0,
            "attacks_detected": 0,
            "defenses_triggered": 0,
            "threats_blocked": 0,
            "start_time": datetime.now(timezone.utc).isoformat()
        }

        self.refresh_baseline()

    def _detect_default_interface(self) -> str:
        """Attempt to find primary active network interface."""
        try:
            if platform.system() == "Darwin":
                # macOS default route interface
                output = subprocess.check_output(["route", "-n", "get", "default"], text=True, stderr=subprocess.DEVNULL)
                for line in output.splitlines():
                    if "interface:" in line:
                        return line.split(":")[1].strip()
            elif platform.system() == "Linux":
                output = subprocess.check_output(["ip", "route", "show", "default"], text=True, stderr=subprocess.DEVNULL)
                parts = output.split()
                if "dev" in parts:
                    return parts[parts.index("dev") + 1]
        except Exception:
            pass
        return "en0" if platform.system() == "Darwin" else "eth0"

    def refresh_baseline(self):
        """Discovers default gateway IP and MAC to establish a trustworthy baseline."""
        try:
            # Get default gateway IP
            if platform.system() == "Darwin":
                output = subprocess.check_output(["route", "-n", "get", "default"], text=True, stderr=subprocess.DEVNULL)
                for line in output.splitlines():
                    if "gateway:" in line:
                        self.gateway_ip = line.split(":")[1].strip()
            elif platform.system() == "Linux":
                output = subprocess.check_output(["ip", "route", "show", "default"], text=True, stderr=subprocess.DEVNULL)
                parts = output.split()
                if "via" in parts:
                    self.gateway_ip = parts[parts.index("via") + 1]
        except Exception:
            if not self.gateway_ip:
                self.gateway_ip = "192.168.1.1"

        # Resolve gateway MAC from local ARP cache
        if self.gateway_ip:
            self.gateway_mac = self._query_arp_cache(self.gateway_ip)
            if self.gateway_mac and not self.baseline_gateway_mac:
                self.baseline_gateway_mac = self.gateway_mac.lower()

        # Resolve local IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self.local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            self.local_ip = "127.0.0.1"

    def _query_arp_cache(self, ip: str) -> Optional[str]:
        """Queries OS ARP table for a specific IP."""
        try:
            output = subprocess.check_output(["arp", "-n", ip], text=True, stderr=subprocess.DEVNULL)
            # Match standard MAC address pattern xx:xx:xx:xx:xx:xx or x:x:x:x:x:x
            match = re.search(r"(([0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2})", output)
            if match:
                return match.group(1).lower()
        except Exception:
            pass
        return None

    def record_ip_mac(self, ip: str, mac: str) -> bool:
        """
        Records an observed IP -> MAC mapping.
        Returns True if a conflicting/spoofed mapping is detected for this IP.
        """
        mac = mac.lower()
        if ip not in self.ip_mac_history:
            self.ip_mac_history[ip] = set()

        is_conflict = False
        if len(self.ip_mac_history[ip]) > 0 and mac not in self.ip_mac_history[ip]:
            # This IP was previously associated with another MAC address!
            is_conflict = True

        self.ip_mac_history[ip].add(mac)
        self.arp_table[ip] = mac
        return is_conflict

    def mark_quarantined(self, mac: str, ip: str, threat_type: str):
        self.quarantined_attackers[mac.lower()] = {
            "ip": ip,
            "threat_type": threat_type,
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "quarantined": True
        }
        self.metrics["threats_blocked"] += 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "interface": self.interface,
            "local_ip": self.local_ip,
            "gateway_ip": self.gateway_ip,
            "gateway_mac": self.gateway_mac,
            "baseline_gateway_mac": self.baseline_gateway_mac,
            "arp_table": self.arp_table,
            "quarantined_attackers": self.quarantined_attackers,
            "metrics": self.metrics
        }
