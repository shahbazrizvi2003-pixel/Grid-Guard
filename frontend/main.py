"""
GridGuard — FastAPI Application
Serves the real-time dashboard and all API endpoints.
WebSocket pushes live threat data every 2 seconds.
"""

import asyncio
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone


from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

from config import configure_environment

configure_environment()

from frontend.state import (
    get_dashboard_snapshot,
    set_approval_result,
    get_timeline,
    get_all_node_states,
    get_incident_history,
    get_incident_replay,
    has_pending_approval,
)
from tools.report_generator import get_all_reports
from observability.evaluators import get_incident_evaluations, get_phoenix_stats

@asynccontextmanager
async def lifespan(_: FastAPI):
    from runtime import start_runtime, stop_runtime
    start_runtime()
    try:
        yield
    finally:
        stop_runtime()


# ── App setup ─────────────────────────────────────────────────────────────────
app = FastAPI(
    title="GridGuard",
    description="Autonomous SCADA Cyber Threat Response — Google Cloud Hackathon",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
_static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=_static_dir), name="static")

# ── WebSocket connection manager ──────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.add(ws)

    def disconnect(self, ws: WebSocket):
        self.active.discard(ws)

    async def broadcast(self, data: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the main dashboard."""
    html_path = os.path.join(_static_dir, "index.html")
    with open(html_path, encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.get("/health")
async def health():
    """Cloud Run health check endpoint."""
    return {"status": "ok", "service": "gridguard", "timestamp": datetime.now(timezone.utc).isoformat()}


# ── WebSocket ─────────────────────────────────────────────────────────────────

@app.websocket("/ws/threats")
async def threat_stream(websocket: WebSocket):
    """Push live dashboard state to connected clients every 2 seconds."""
    await manager.connect(websocket)
    try:
        while True:
            snapshot = get_dashboard_snapshot()
            await websocket.send_json(snapshot)
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


# ── REST API ──────────────────────────────────────────────────────────────────

@app.post("/api/inject-attack/{attack_type}")
async def inject_attack(attack_type: str, background_tasks: BackgroundTasks):
    """
    Inject an attack scenario (demo control panel).
    Triggers the SCADA simulator and starts the agent pipeline.
    """
    valid_types = {"ransomware", "unauthorized_access", "ddos", "data_exfiltration"}
    if attack_type not in valid_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid attack type. Must be one of: {valid_types}"
        )

    # Import here to avoid circular imports at module load
    from simulator.scada_simulator import simulator
    from agents.pipeline_runner import _active_pipelines, _PIPELINE_TIMEOUT_S
    import time as _time

    # Check if same attack type is already running
    started_at = _active_pipelines.get(attack_type)
    if started_at and (_time.time() - started_at) < _PIPELINE_TIMEOUT_S:
        return {
            "status": "already_running",
            "attack_type": attack_type,
            "message": f"A {attack_type} pipeline is already running. Wait for it to finish.",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    result = simulator.inject_attack(attack_type)
    node_id = result["target_node"]

    # Run agent pipeline in background (non-blocking)
    background_tasks.add_task(
        _run_pipeline_background,
        attack_type=attack_type,
        node_id=node_id,
        telemetry_snapshot=result.get("telemetry_snapshot"),
    )

    return {
        "status": "injected",
        "attack_type": attack_type,
        "target_node": node_id,
        "pipeline_status": "starting",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.post("/api/approve/{incident_id}")
async def approve_response(incident_id: str, approved: bool = True):
    """Human approval gate — operator approves or rejects CRITICAL threat response."""
    if not has_pending_approval(incident_id):
        raise HTTPException(status_code=404, detail="No pending approval for this incident")
    result = "approved" if approved else "rejected"
    set_approval_result(incident_id, result)
    return {
        "incident_id": incident_id,
        "status": result,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.post("/api/escalate/{incident_id}")
async def escalate_incident(incident_id: str):
    """Escalate a pending incident to SOC team."""
    if not has_pending_approval(incident_id):
        raise HTTPException(status_code=404, detail="No pending approval for this incident")
    set_approval_result(incident_id, "escalated")
    return {
        "incident_id": incident_id,
        "status": "escalated",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/api/reports")
async def get_reports():
    """Return all generated incident reports."""
    return {"reports": get_all_reports()}


@app.get("/api/timeline")
async def get_timeline_api():
    """Return the agent decision timeline."""
    return {"events": get_timeline()}


@app.get("/api/nodes")
async def get_nodes():
    """Return current state of all grid nodes."""
    return {"nodes": get_all_node_states()}


@app.get("/api/phoenix-stats")
async def phoenix_stats():
    """Return live Arize Phoenix observability stats for dashboard panel."""
    stats = get_phoenix_stats()
    return stats


@app.get("/api/evaluations")
async def incident_evaluations():
    """Return post-incident grounding and response-quality results."""
    return {"evaluations": get_incident_evaluations()}


@app.get("/api/status")
async def system_status():
    """Return overall GridGuard system status."""
    from observability.phoenix_mcp import get_phoenix_mcp_status
    from simulator.scada_simulator import simulator
    snapshot = get_dashboard_snapshot()
    return {
        "system": "GridGuard",
        "version": "1.0.0",
        "environment": os.getenv("GRIDGUARD_ENV", "development"),
        "simulator_running": simulator._running,
        "node_count": len(snapshot.get("node_states", {})),
        "active_incidents": len(snapshot.get("active_incidents", [])),
        "pending_approvals": len(snapshot.get("pending_approvals", [])),
        "model": os.getenv("GRIDGUARD_MODEL", "gemini-3-flash-preview"),
        "phoenix_url": os.getenv("PHOENIX_BASE_URL", "https://app.phoenix.arize.com"),
        "phoenix_project": os.getenv("PHOENIX_PROJECT_NAME", "gridguard"),
        "phoenix_mcp": get_phoenix_mcp_status(),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/api/incidents")
async def incident_history():
    return {"incidents": get_incident_history()}


@app.get("/api/incidents/{incident_id}/replay")
async def incident_replay(incident_id: str):
    replay = get_incident_replay(incident_id)
    if replay is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return replay


# ── Background task helper ────────────────────────────────────────────────────

async def _run_pipeline_background(
    attack_type: str,
    node_id: str,
    telemetry_snapshot: dict | None = None,
):
    """Run the agent pipeline as a background task."""
    try:
        from agents.pipeline_runner import run_pipeline_for_attack
        await run_pipeline_for_attack(
            attack_type=attack_type,
            node_id=node_id,
            telemetry_snapshot=dict(telemetry_snapshot) if telemetry_snapshot else None,
        )
    except Exception as e:
        from frontend.state import add_timeline_event
        add_timeline_event(
            agent_name="system",
            action="pipeline_background_error",
            reasoning=f"Background pipeline error: {str(e)[:200]}",
            confidence=0.0,
            outcome="error",
            severity="HIGH" 
        )
