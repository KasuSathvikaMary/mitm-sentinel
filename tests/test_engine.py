import pytest
from src.core.engine import MITMSentinelEngine
from src.simulator.attack_simulator import AttackSimulator

def test_engine_pipeline_and_simulation():
    engine = MITMSentinelEngine()
    engine.network_state.gateway_ip = "192.168.1.1"
    engine.network_state.baseline_gateway_mac = "11:22:33:44:55:66"

    alerts_received = []
    def on_alert(event):
        alerts_received.append(event.data)

    engine.event_bus.subscribe("ALERT", on_alert)

    sim = AttackSimulator(engine)
    # Inject simulated gateway poisoning
    sim.simulate_arp_gateway_poisoning(
        gateway_ip="192.168.1.1",
        attacker_mac="de:ad:be:ef:13:37"
    )

    assert len(alerts_received) == 1
    assert alerts_received[0]["threat_type"] == "ARP_GATEWAY_POISONING"
    assert engine.network_state.metrics["attacks_detected"] >= 1
    assert engine.network_state.metrics["defenses_triggered"] >= 1
    assert "de:ad:be:ef:13:37" in engine.network_state.quarantined_attackers
