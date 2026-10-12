"""
DNS Spoofing & Cache Poisoning Detection Engine.
Detects:
1. Unsolicited DNS responses (Transaction ID matching bypass).
2. Forged A/AAAA records by cross-checking against trusted DNS-over-HTTPS (DoH).
3. Private IP spoofing (Public domain resolved to RFC 1918 private IP).
"""
import time
import requests
import ipaddress
from typing import Dict, Any, Optional, List
from src.detectors.base_detector import BaseDetector, ThreatAlert

class DNSSpoofDetector(BaseDetector):
    def __init__(self, config: Dict[str, Any], network_state):
        super().__init__("DNS_Spoof_Detector", config, network_state)
        self.doh_verification = config.get("doh_verification", True)
        self.doh_resolvers = config.get("doh_resolvers", [
            "https://cloudflare-dns.com/dns-query",
            "https://dns.google/resolve"
        ])
        self.unsolicited_response_alert = config.get("unsolicited_response_alert", True)

        # Track active DNS queries: id -> {query_name, timestamp, client_ip}
        self.active_queries: Dict[int, Dict[str, Any]] = {}

    def analyze(self, packet: Dict[str, Any]) -> Optional[ThreatAlert]:
        if not self.enabled or packet.get("type") != "DNS":
            return None

        is_response = packet.get("is_response", False)
        dns_id = packet.get("dns_id")
        query_name = packet.get("query_name", "").rstrip(".")
        now = time.time()

        # Track outgoing request
        if not is_response:
            if dns_id is not None:
                self.active_queries[dns_id] = {
                    "query_name": query_name,
                    "timestamp": now,
                    "client_ip": packet.get("src_ip")
                }
            return None

        # Process response
        answers = packet.get("answers", [])
        src_ip = packet.get("src_ip") # DNS server IP

        # 1. Unsolicited DNS Response Detection
        matched_query = self.active_queries.pop(dns_id, None) if dns_id is not None else None
        if self.unsolicited_response_alert and matched_query is None:
            # Response arrived with no prior query
            return ThreatAlert(
                threat_type="UNSOLICITED_DNS_RESPONSE",
                severity="HIGH",
                description=f"Received unsolicited DNS response (TxID: {dns_id}) for {query_name} without preceding query.",
                attacker_ip=src_ip,
                victim_ip=packet.get("dst_ip"),
                evidence={
                    "dns_id": dns_id,
                    "query_name": query_name,
                    "answers": answers
                },
                recommended_action="block_dns_source_and_fallback_doh"
            )

        # 2. Check for Private IP resolution for Public Domains (DNS Rebinding / Local Attacker Redirect)
        if query_name and answers:
            # If query is a public domain like bank.com or google.com but returns RFC1918 private IP
            is_public_domain = "." in query_name and not query_name.endswith(".local") and not query_name.endswith(".internal")
            for ans in answers:
                try:
                    ip_obj = ipaddress.ip_address(ans)
                    if is_public_domain and ip_obj.is_private:
                        return ThreatAlert(
                            threat_type="DNS_SPOOF_PRIVATE_IP_HIJACK",
                            severity="CRITICAL",
                            description=f"DNS Hijack: Public domain '{query_name}' resolved to private network IP '{ans}' by {src_ip}.",
                            attacker_ip=src_ip,
                            victim_ip=packet.get("dst_ip"),
                            evidence={
                                "query_name": query_name,
                                "spoofed_ip": ans,
                                "dns_server": src_ip
                            },
                            recommended_action="flush_dns_and_force_doh"
                        )
                except ValueError:
                    pass

        # 3. DoH Cross-Verification for Discrepancy Detection
        if self.doh_verification and query_name and answers:
            doh_answers = self._query_doh(query_name)
            if doh_answers:
                # If local answer doesn't overlap with any DoH trusted answer
                local_ips = set(answers)
                doh_ips = set(doh_answers)
                if local_ips and doh_ips and not local_ips.intersection(doh_ips):
                    return ThreatAlert(
                        threat_type="DNS_POISONING_DOH_MISMATCH",
                        severity="CRITICAL",
                        description=f"DNS Poisoning Detected for '{query_name}'. Local DNS resolved to {list(local_ips)}, but trusted DoH returned {list(doh_ips)}.",
                        attacker_ip=src_ip,
                        victim_ip=packet.get("dst_ip"),
                        evidence={
                            "domain": query_name,
                            "local_answers": list(local_ips),
                            "doh_trusted_answers": list(doh_ips)
                        },
                        recommended_action="flush_dns_and_force_doh"
                    )

        return None

    def _query_doh(self, domain: str) -> List[str]:
        """Query Cloudflare DoH endpoint for trusted DNS resolution."""
        try:
            url = f"{self.doh_resolvers[0]}?name={domain}&type=A"
            headers = {"Accept": "application/dns-json"}
            resp = requests.get(url, headers=headers, timeout=2.0)
            if resp.status_code == 200:
                data = resp.json()
                answers = []
                for ans in data.get("Answer", []):
                    if ans.get("type") == 1: # A record
                        answers.append(ans.get("data"))
                return answers
        except Exception:
            pass
        return []
