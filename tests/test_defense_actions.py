import pytest
from src.core.network_state import NetworkState
from src.detectors.base_detector import ThreatAlert
from src.defense.arp_immunity import ARPImmunityDefense
from src.defense.firewall_blocker import FirewallBlockerDefense
from src.defense.dns_sec_enforcer import DNSSecEnforcerDefense

def test_arp_immunity_defense():
    state = NetworkState(interface="test0")
    state.gateway_ip = "192.168.1.1"
    state.baseline_gateway_mac = "00:11:22:33:44:55"

    defense = ARPImmunityDefense({"enabled": True, "counter_arp_announcements": 1}, state)
    alert = ThreatAlert(
        threat_type="ARP_GATEWAY_POISONING",
        severity="CRITICAL",
        description="Gateway poisoned",
        attacker_mac="de:ad:be:ef:13:37"
    )

    result = defense.execute(alert)
    assert result.success is True
    assert state.arp_table.get("192.168.1.1") == "00:11:22:33:44:55"

def test_firewall_quarantine_defense():
    state = NetworkState(interface="test0")
    defense = FirewallBlockerDefense({"enabled": True, "isolation_duration_seconds": 60}, state)

    alert = ThreatAlert(
        threat_type="ARP_GATEWAY_POISONING",
        severity="CRITICAL",
        description="Gateway poisoned",
        attacker_ip="192.168.1.188",
        attacker_mac="de:ad:be:ef:13:37"
    )

    result = defense.execute(alert)
    assert result.success is True
    assert "de:ad:be:ef:13:37" in state.quarantined_attackers
    assert state.quarantined_attackers["de:ad:be:ef:13:37"]["quarantined"] is True
    assert state.metrics["threats_blocked"] == 1

def test_dns_sec_enforcer_defense():
    state = NetworkState(interface="test0")
    defense = DNSSecEnforcerDefense({"enabled": True}, state)

    alert = ThreatAlert(
        threat_type="DNS_POISONING_DOH_MISMATCH",
        severity="CRITICAL",
        description="DNS mismatch"
    )

    result = defense.execute(alert)
    assert result.success is True
    assert "DoH" in result.message or "DNS" in result.message
