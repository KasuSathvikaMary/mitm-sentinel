"""
Safe Attack Simulator & Evaluation Engine.
Generates controlled, synthetic MITM attack vectors to test, demonstrate, and verify
detection and automated defense countermeasures without disrupting production networks.
"""
import time
import threading
from typing import Optional, Callable, Dict, Any

class AttackSimulator:
    def __init__(self, engine, packet_callback: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.engine = engine
        self.feed_packet = packet_callback or self.engine.packet_capture.feed_packet
        self.is_running = False

    def simulate_arp_gateway_poisoning(
        self,
        gateway_ip: Optional[str] = None,
        attacker_mac: str = "de:ad:be:ef:13:37",
        victim_ip: Optional[str] = None
    ):
        """Simulates an ARP spoof attack where attacker claims to be the default gateway."""
        gw_ip = gateway_ip or self.engine.network_state.gateway_ip or "192.168.1.1"
        target_ip = victim_ip or self.engine.network_state.local_ip or "192.168.1.50"

        pkt = {
            "timestamp": time.time(),
            "type": "ARP",
            "arp_op": "reply",
            "src_ip": gw_ip,
            "src_mac": attacker_mac,
            "dst_ip": target_ip,
            "dst_mac": "aa:bb:cc:dd:ee:ff",
            "summary": f"ARP reply {gw_ip} is-at {attacker_mac} (Poisoning Gateway)",
            "layers": ["ARP"]
        }
        self.feed_packet(pkt)
        return pkt

    def simulate_arp_reply_flood(
        self,
        attacker_ip: str = "192.168.1.188",
        attacker_mac: str = "00:11:22:33:44:55",
        count: int = 10
    ):
        """Simulates an aggressive burst of unsolicited ARP replies."""
        pkts = []
        for _ in range(count):
            pkt = {
                "timestamp": time.time(),
                "type": "ARP",
                "arp_op": "reply",
                "src_ip": attacker_ip,
                "src_mac": attacker_mac,
                "dst_ip": self.engine.network_state.local_ip or "192.168.1.50",
                "dst_mac": "aa:bb:cc:dd:ee:ff",
                "summary": f"ARP reply {attacker_ip} is-at {attacker_mac} [Burst]",
                "layers": ["ARP"]
            }
            self.feed_packet(pkt)
            pkts.append(pkt)
            time.sleep(0.02)
        return pkts

    def simulate_dns_poisoning(
        self,
        domain: str = "secure-bank.example.com",
        forged_ip: str = "192.168.1.200",
        dns_server_ip: str = "192.168.1.1"
    ):
        """Simulates a forged DNS response resolving a public domain to a local attacker IP."""
        # 1. First record legitimate query
        dns_id = 42133
        self.feed_packet({
            "timestamp": time.time(),
            "type": "DNS",
            "is_response": False,
            "dns_id": dns_id,
            "query_name": domain,
            "src_ip": self.engine.network_state.local_ip or "192.168.1.50",
            "dst_ip": dns_server_ip,
            "summary": f"DNS Query {domain} (TxID: {dns_id})",
            "layers": ["DNS"]
        })

        time.sleep(0.05)

        # 2. Poisoned response claiming domain is at local attacker IP
        pkt = {
            "timestamp": time.time(),
            "type": "DNS",
            "is_response": True,
            "dns_id": dns_id,
            "query_name": domain,
            "answers": [forged_ip],
            "src_ip": dns_server_ip,
            "dst_ip": self.engine.network_state.local_ip or "192.168.1.50",
            "summary": f"DNS Response {domain} -> {forged_ip} [Poisoned]",
            "layers": ["DNS"]
        }
        self.feed_packet(pkt)
        return pkt

    def simulate_ssl_stripping(
        self,
        target_domain: str = "paypal.com",
        attacker_ip: str = "192.168.1.105"
    ):
        """Simulates an SSL Stripping (HTTP downgrade) scenario."""
        pkt = {
            "timestamp": time.time(),
            "type": "HTTP",
            "http_method": "POST",
            "http_host": target_domain,
            "dport": 80,
            "sport": 54321,
            "src_ip": self.engine.network_state.local_ip or "192.168.1.50",
            "dst_ip": attacker_ip,
            "proxy_ip": attacker_ip,
            "is_ssl_stripped": True,
            "summary": f"Plaintext HTTP POST {target_domain}:80 (SSL Stripped!)",
            "layers": ["TCP", "HTTP"]
        }
        self.feed_packet(pkt)
        return pkt

    def simulate_mitm_proxy_cert(
        self,
        target_domain: str = "api.github.com",
        proxy_ca: str = "mitmproxy",
        attacker_ip: str = "192.168.1.105"
    ):
        """Simulates TLS handshake interception with a known MITM proxy root certificate."""
        pkt = {
            "timestamp": time.time(),
            "type": "TLS",
            "src_ip": attacker_ip,
            "dst_ip": self.engine.network_state.local_ip or "192.168.1.50",
            "certificate_info": {
                "subject": target_domain,
                "issuer": f"CN={proxy_ca}, O={proxy_ca} Root CA",
                "is_self_signed": False
            },
            "summary": f"TLS Certificate intercepted by {proxy_ca}",
            "layers": ["TCP", "TLS"]
        }
        self.feed_packet(pkt)
        return pkt

    def run_full_evaluation_scenario(self):
        """Executes an end-to-end multi-vector attack test suite."""
        print("\n🚀 [SIMULATOR] Launching Full Evaluation Scenario...")

        print("1. Injecting ARP Gateway Poisoning Attack...")
        self.simulate_arp_gateway_poisoning()
        time.sleep(0.3)

        print("2. Injecting ARP Reply Storm...")
        self.simulate_arp_reply_flood(count=8)
        time.sleep(0.3)

        print("3. Injecting DNS Poisoning Attack...")
        self.simulate_dns_poisoning()
        time.sleep(0.3)

        print("4. Injecting SSL Stripping Attack...")
        self.simulate_ssl_stripping()
        time.sleep(0.3)

        print("5. Injecting MITM Proxy CA Interception...")
        self.simulate_mitm_proxy_cert()
        time.sleep(0.3)

        print("✅ [SIMULATOR] Scenario Completed.\n")
