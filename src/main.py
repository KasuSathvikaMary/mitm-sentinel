"""
MITM Sentinel - Main CLI Entrypoint.
Provides commands:
  monitor   - Start live packet sniffing, detection, and automatic defense.
  web       - Launch interactive Cyber Defense Web Dashboard & API.
  simulate  - Run safe, built-in attack vectors to evaluate detection and defense.
  status    - Display network baseline, gateway MAC, and security telemetry.
"""
import argparse
import sys
import os
import time
import uvicorn

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.engine import MITMSentinelEngine
from src.simulator.attack_simulator import AttackSimulator

def print_banner():
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                 🛡️  M I T M - S E N T I N E L                  ║
    ║        Man-in-the-Middle Attack Detection & Defense           ║
    ║              Autonomous Network Protection Suite              ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def cmd_status(args):
    print_banner()
    engine = MITMSentinelEngine(args.config)
    state = engine.network_state
    print("🌐 [NETWORK BASELINE STATE]")
    print(f"  Interface:             {state.interface}")
    print(f"  Local IP:              {state.local_ip}")
    print(f"  Gateway IP:            {state.gateway_ip}")
    print(f"  Gateway Baseline MAC:  {state.baseline_gateway_mac or 'Unresolved'}")
    print(f"  Auto-Remediate:        {'ENABLED' if engine.auto_remediate else 'DISABLED'}")
    print(f"  Active Detectors:      {[d.name for d in engine.detectors]}")
    print(f"  Active Defenses:       {list(engine.defenses.keys())}")
    print(f"  Quarantined Hosts:     {len(state.quarantined_attackers)}")

def cmd_simulate(args):
    print_banner()
    print("🧪 Running Autonomous Attack Simulation & Defense Verification...\n")
    engine = MITMSentinelEngine(args.config)

    # Listen to events on console
    def on_alert(event):
        alert = event.data
        print(f"\n🚨 [DETECTION ALERT] [{alert.get('severity')}] {alert.get('threat_type')}")
        print(f"   Description: {alert.get('description')}")
        print(f"   Attacker:    {alert.get('attacker_ip')} ({alert.get('attacker_mac')})")

    def on_defense(event):
        d = event.data
        print(f"🛡️  [DEFENSE ACTION] {d.get('action_name')}: {d.get('message')}")
        for act in d.get("details", {}).get("actions", []):
            print(f"   ↳ {act}")

    engine.event_bus.subscribe("ALERT", on_alert)
    engine.event_bus.subscribe("DEFENSE", on_defense)

    sim = AttackSimulator(engine)
    sim.run_full_evaluation_scenario()

    metrics = engine.network_state.metrics
    print("\n📊 [EVALUATION SUMMARY]")
    print(f"  Packets Ingested:    {metrics['packets_analyzed']}")
    print(f"  Attacks Detected:    {metrics['attacks_detected']}")
    print(f"  Defenses Triggered:  {metrics['defenses_triggered']}")
    print(f"  Threats Blocked:     {metrics['threats_blocked']}")

def cmd_web(args):
    print_banner()
    from src.web.app import create_web_app
    engine = MITMSentinelEngine(args.config)

    # Start live capture in background if requested
    if args.live:
        try:
            print(f"🔍 Starting background live packet capture on {engine.network_state.interface}...")
            engine.start_live_capture()
        except Exception as e:
            print(f"⚠️ Live capture warning: {e}. Running in simulation/event mode.")

    app = create_web_app(engine)
    print(f"\n🌐 Web Dashboard running at http://{args.host}:{args.port}")
    print(f"Press Ctrl+C to exit.\n")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")

def cmd_monitor(args):
    print_banner()
    engine = MITMSentinelEngine(args.config)

    def on_alert(event):
        alert = event.data
        print(f"\n🚨 [ALERT] [{alert.get('severity')}] {alert.get('threat_type')}")
        print(f"   {alert.get('description')}")

    def on_defense(event):
        d = event.data
        print(f"🛡️ [DEFENSE] {d.get('action_name')}: {d.get('message')}")

    engine.event_bus.subscribe("ALERT", on_alert)
    engine.event_bus.subscribe("DEFENSE", on_defense)

    print(f"🔍 Starting MITM Sentinel Active Guard on interface '{engine.network_state.interface}'...")
    print(f"Default Gateway baseline MAC: {engine.network_state.baseline_gateway_mac}")
    print("Press Ctrl+C to terminate.")

    try:
        engine.start_live_capture()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping MITM Sentinel...")
        engine.stop()

def main():
    parser = argparse.ArgumentParser(description="MITM Sentinel - Attack Detection & Defense")
    parser.add_argument("--config", "-c", default="config/config.yaml", help="Path to YAML configuration")

    subparsers = parser.add_subparsers(dest="command")

    # Status
    subparsers.add_parser("status", help="Show system baseline & telemetry status")

    # Simulate
    subparsers.add_parser("simulate", help="Run safe simulated attack test suite")

    # Web
    web_parser = subparsers.add_parser("web", help="Launch interactive Web Dashboard")
    web_parser.add_argument("--host", default="127.0.0.1", help="Dashboard host")
    web_parser.add_argument("--port", type=int, default=8080, help="Dashboard port")
    web_parser.add_argument("--live", action="store_true", help="Enable live sniffing alongside web dashboard")

    # Monitor
    subparsers.add_parser("monitor", help="Start active live packet monitoring")

    args = parser.parse_args()
    if not args.command:
        # Default to simulate if no subcommand provided
        args.command = "simulate"

    if args.command == "status":
        cmd_status(args)
    elif args.command == "simulate":
        cmd_simulate(args)
    elif args.command == "web":
        cmd_web(args)
    elif args.command == "monitor":
        cmd_monitor(args)

if __name__ == "__main__":
    main()
