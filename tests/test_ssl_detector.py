import pytest
from src.core.network_state import NetworkState
from src.detectors.ssl_tamper_detector import SSLTamperDetector

def test_mitm_proxy_ca_detection():
    state = NetworkState(interface="test0")
    detector = SSLTamperDetector({
        "check_known_mitm_issuers": True,
        "known_mitm_ca_signatures": ["mitmproxy", "PortSwigger", "Charles Proxy"]
    }, state)

    pkt = {
        "type": "TLS",
        "src_ip": "192.168.1.150",
        "dst_ip": "192.168.1.50",
        "certificate_info": {
            "subject": "github.com",
            "issuer": "CN=mitmproxy, O=mitmproxy Root CA",
            "is_self_signed": False
        }
    }

    alert = detector.analyze(pkt)
    assert alert is not None
    assert alert.threat_type == "MITM_PROXY_CERT_INTERCEPTION"
    assert alert.severity == "CRITICAL"

def test_ssl_stripping_detection():
    state = NetworkState(interface="test0")
    detector = SSLTamperDetector({
        "detect_http_downgrade": True
    }, state)

    pkt = {
        "type": "HTTP",
        "http_method": "POST",
        "http_host": "paypal.com",
        "dport": 80,
        "src_ip": "192.168.1.50",
        "dst_ip": "192.168.1.200",
        "is_ssl_stripped": True
    }

    alert = detector.analyze(pkt)
    assert alert is not None
    assert alert.threat_type == "SSL_STRIPPING_ATTACK"
    assert alert.severity == "CRITICAL"
