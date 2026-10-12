import pytest
from src.core.network_state import NetworkState
from src.detectors.dns_spoof_detector import DNSSpoofDetector

def test_unsolicited_dns_response_detection():
    state = NetworkState(interface="test0")
    detector = DNSSpoofDetector({
        "unsolicited_response_alert": True,
        "doh_verification": False
    }, state)

    # Arriving response without any prior query recorded
    unsolicited_pkt = {
        "type": "DNS",
        "is_response": True,
        "dns_id": 9999,
        "query_name": "unknown-domain.com",
        "answers": ["1.2.3.4"],
        "src_ip": "192.168.1.1",
        "dst_ip": "192.168.1.50"
    }

    alert = detector.analyze(unsolicited_pkt)
    assert alert is not None
    assert alert.threat_type == "UNSOLICITED_DNS_RESPONSE"
    assert alert.severity == "HIGH"

def test_dns_private_ip_hijack_detection():
    state = NetworkState(interface="test0")
    detector = DNSSpoofDetector({
        "unsolicited_response_alert": False,
        "doh_verification": False
    }, state)

    # Simulate recorded query
    detector.active_queries[1234] = {
        "query_name": "secure-banking.com",
        "timestamp": 1000.0,
        "client_ip": "192.168.1.50"
    }

    # Public domain resolved to RFC1918 private IP (local attacker IP)
    poisoned_resp = {
        "type": "DNS",
        "is_response": True,
        "dns_id": 1234,
        "query_name": "secure-banking.com",
        "answers": ["192.168.1.100"],
        "src_ip": "192.168.1.1",
        "dst_ip": "192.168.1.50"
    }

    alert = detector.analyze(poisoned_resp)
    assert alert is not None
    assert alert.threat_type == "DNS_SPOOF_PRIVATE_IP_HIJACK"
    assert alert.severity == "CRITICAL"
