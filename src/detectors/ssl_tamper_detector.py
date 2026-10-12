"""
SSL/TLS Tampering and Stripping (HTTP Downgrade) Detector.
Detects:
1. MITM Proxy CA signatures (mitmproxy, Burp Suite, Charles Proxy, Fiddler).
2. Self-signed or untrusted certificate interception.
3. SSL Stripping: Cleartext HTTP traffic directed to known HTTPS-only domains.
"""
from typing import Dict, Any, Optional, List
from src.detectors.base_detector import BaseDetector, ThreatAlert

KNOWN_HSTS_DOMAINS = {
    "google.com", "facebook.com", "twitter.com", "x.com", "github.com",
    "paypal.com", "bankofamerica.com", "chase.com", "amazon.com", "apple.com"
}

class SSLTamperDetector(BaseDetector):
    def __init__(self, config: Dict[str, Any], network_state):
        super().__init__("SSL_Tamper_Detector", config, network_state)
        self.check_self_signed = config.get("check_self_signed", True)
        self.known_mitm_ca_signatures = config.get("known_mitm_ca_signatures", [
            "mitmproxy", "PortSwigger", "Charles Proxy", "Fiddler", "Burp Suite"
        ])
        self.detect_http_downgrade = config.get("detect_http_downgrade", True)

    def analyze(self, packet: Dict[str, Any]) -> Optional[ThreatAlert]:
        if not self.enabled:
            return None

        pkt_type = packet.get("type")

        # 1. SSL Stripping / HTTP Downgrade Detection
        if pkt_type == "HTTP" and self.detect_http_downgrade:
            dst_ip = packet.get("dst_ip")
            src_ip = packet.get("src_ip")
            dport = packet.get("dport", 80)
            host = packet.get("http_host", "")

            # If request is unencrypted port 80 to a strictly HTTPS domain
            if dport == 80:
                is_known_hsts = any(h in host.lower() for h in KNOWN_HSTS_DOMAINS)
                if is_known_hsts or packet.get("is_ssl_stripped"):
                    return ThreatAlert(
                        threat_type="SSL_STRIPPING_ATTACK",
                        severity="CRITICAL",
                        description=f"SSL Stripping Detected: Unencrypted HTTP request to strict HTTPS domain '{host or dst_ip}'. Connection hijacked.",
                        attacker_ip=packet.get("proxy_ip") or dst_ip,
                        victim_ip=src_ip,
                        evidence={
                            "target_host": host,
                            "port": dport,
                            "method": packet.get("http_method", "GET")
                        },
                        recommended_action="kill_connection_and_enforce_https"
                    )

        # 2. Certificate Tampering Analysis (fed via certificate probe or TLS parser)
        cert_info = packet.get("certificate_info")
        if cert_info:
            issuer = cert_info.get("issuer", "")
            is_self_signed = cert_info.get("is_self_signed", False)

            # Check known MITM proxy root CAs
            for sig in self.known_mitm_ca_signatures:
                if sig.lower() in issuer.lower():
                    return ThreatAlert(
                        threat_type="MITM_PROXY_CERT_INTERCEPTION",
                        severity="CRITICAL",
                        description=f"Active MITM Interception: TLS certificate issued by known interception proxy '{sig}' ({issuer}).",
                        attacker_ip=packet.get("src_ip"),
                        victim_ip=packet.get("dst_ip"),
                        evidence={
                            "issuer": issuer,
                            "subject": cert_info.get("subject"),
                            "proxy_signature": sig
                        },
                        recommended_action="kill_connection_and_isolate"
                    )

            # Check untrusted self-signed certificate in public traffic
            if is_self_signed and self.check_self_signed:
                return ThreatAlert(
                    threat_type="SELF_SIGNED_CERT_HIJACK",
                    severity="HIGH",
                    description=f"Suspicious self-signed certificate detected for domain {cert_info.get('subject')}.",
                    attacker_ip=packet.get("src_ip"),
                    victim_ip=packet.get("dst_ip"),
                    evidence={
                        "subject": cert_info.get("subject"),
                        "issuer": issuer
                    },
                    recommended_action="warn_user_and_inspect"
                )

        return None
