"""
FastAPI Web Dashboard & Telemetry Server.
Provides:
- WebSocket endpoint for streaming real-time packets, threat alerts, and defense actions.
- REST endpoints for system state, quarantine status, and triggering simulations.
"""
import asyncio
import json
import os
from typing import List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

def create_web_app(engine):
    app = FastAPI(title="MITM Sentinel Dashboard", version="1.0.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Active WebSocket clients
    connected_clients: List[WebSocket] = []

    # Listen to Engine EventBus and broadcast to WebSockets
    def handle_bus_event(event):
        if not connected_clients:
            return
        payload = event.to_dict()
        message = json.dumps(payload)
        # Broadcast asynchronously to all connected websocket clients
        for client in list(connected_clients):
            try:
                asyncio.run_coroutine_threadsafe(client.send_text(message), loop=app.state.event_loop)
            except Exception:
                pass

    engine.event_bus.subscribe("*", handle_bus_event)

    static_dir = os.path.join(os.path.dirname(__file__), "static")
    if os.path.exists(static_dir):
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.on_event("startup")
    async def startup_event():
        app.state.event_loop = asyncio.get_running_loop()

    @app.get("/", response_class=HTMLResponse)
    async def get_index():
        index_file = os.path.join(static_dir, "index.html")
        if os.path.exists(index_file):
            with open(index_file, "r", encoding="utf-8") as f:
                return f.read()
        return "<h1>MITM Sentinel Dashboard</h1><p>Static files missing.</p>"

    @app.get("/api/state")
    async def get_state():
        return JSONResponse(engine.network_state.to_dict())

    @app.get("/api/alerts")
    async def get_alerts():
        return JSONResponse(engine.alert_manager.alerts_history)

    @app.post("/api/simulate/{attack_type}")
    async def trigger_simulation(attack_type: str):
        from src.simulator.attack_simulator import AttackSimulator
        sim = AttackSimulator(engine)
        result = {}
        if attack_type == "arp_gateway":
            result = sim.simulate_arp_gateway_poisoning()
        elif attack_type == "arp_flood":
            result = sim.simulate_arp_reply_flood()
        elif attack_type == "dns_poison":
            result = sim.simulate_dns_poisoning()
        elif attack_type == "ssl_strip":
            result = sim.simulate_ssl_stripping()
        elif attack_type == "proxy_cert":
            result = sim.simulate_mitm_proxy_cert()
        elif attack_type == "full_suite":
            sim.run_full_evaluation_scenario()
            result = {"status": "Full scenario initiated"}
        else:
            return JSONResponse({"error": f"Unknown attack type: {attack_type}"}, status_code=400)
        return JSONResponse({"status": "Simulation triggered", "details": result})

    @app.post("/api/defense/toggle")
    async def toggle_auto_remediate():
        engine.auto_remediate = not engine.auto_remediate
        return JSONResponse({"auto_remediate": engine.auto_remediate})

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        await websocket.accept()
        connected_clients.append(websocket)
        # Send initial snapshot
        await websocket.send_text(json.dumps({
            "event_type": "SNAPSHOT",
            "data": {
                "state": engine.network_state.to_dict(),
                "alerts": engine.alert_manager.alerts_history[-20:],
                "auto_remediate": engine.auto_remediate
            }
        }))
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            connected_clients.remove(websocket)
        except Exception:
            if websocket in connected_clients:
                connected_clients.remove(websocket)

    return app
