import pytest
import time
from src.core.network_state import NetworkState
from src.detectors.arp_spoof_detector import ARPSpoofDetector

def test_arp_gateway_mac_flip_detection():
    state = NetworkState(interface="test0")
    state.gateway_ip = "192.168.1.1"
    state.baseline_gateway_mac = "00:aa:bb:cc:dd:ee"

    detector = ARPSpoofDetector({
        "rate_limit_pps": 5,
        "unsolicited_reply_alert": True,
        "gateway_mac_flip_alert": True
    }, state)

    # Legitimate packet matching baseline
    legit_pkt = {
        "type": "ARP",
        "arp_op": "reply",
        "src_ip": "192.168.1.1",
        "src_mac": "00:aa:bb:cc:dd:ee",
        "dst_ip": "192.168.1.50",
        "dst_mac": "11:22:33:44:55:66"
    }
    alert = detector.analyze(legit_pkt)
    assert alert is None

    # Poisoned packet: same gateway IP, different attacker MAC
    poison_pkt = {
        "type": "ARP",
        "arp_op": "reply",
        "src_ip": "192.168.1.1",
        "src_mac": "de:ad:be:ef:13:37",
        "dst_ip": "192.168.1.50",
        "dst_mac": "11:22:33:44:55:66"
    }
    alert = detector.analyze(poison_pkt)
    assert alert is not None
    assert alert.threat_type == "ARP_GATEWAY_POISONING"
    assert alert.severity == "CRITICAL"
    assert alert.attacker_mac == "de:ad:be:ef:13:37"

def test_arp_reply_flood_detection():
    state = NetworkState(interface="test0")
    detector = ARPSpoofDetector({
        "rate_limit_pps": 3,
        "gateway_mac_flip_alert": False,
        "unsolicited_reply_alert": False
    }, state)

    pkt = {
        "type": "ARP",
        "arp_op": "reply",
        "src_ip": "192.168.1.120",
        "src_mac": "aa:bb:cc:11:22:33",
        "dst_ip": "192.168.1.50",
        "dst_mac": "ff:ff:ff:ff:ff:ff"
    }

    # Send up to threshold
    for _ in range(3):
        detector.analyze(pkt)

    # Exceed threshold
    alert = detector.analyze(pkt)
    assert alert is not None
    assert alert.threat_type == "ARP_REPLY_FLOOD"
    assert alert.severity == "HIGH"
