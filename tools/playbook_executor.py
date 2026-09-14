"""
GridGuard — Playbook Executor Tool
Loads and executes JSON response playbooks for detected threats.
Also manages the human approval gate for CRITICAL/HIGH threats.
"""

import json
import asyncio
import time
from pathlib import Path
from typing import Any
from datetime import datetime

PLAYBOOKS_DIR = Path(__file__).parent.parent / "playbooks"
SUPPORTED_PLAYBOOKS = {
    "ransomware",
    "unauthorized_access",
    "ddos",
    "data_exfiltration",
}

# Global approval state — the dashboard writes here, this module reads it
_pending_approvals: dict[str, dict] = {}
_approval_events: dict[str, asyncio.Event] = {}


def _load_playbook(playbook_name: str) -> dict:
    """Load a JSON playbook from the playbooks/ directory."""
    # Normalize name
    safe_name = playbook_name.lower().replace(" ", "_").replace("-", "_")
    if not safe_name.endswith(".json"):
        safe_name += ".json"

    if safe_name.removesuffix(".json") not in SUPPORTED_PLAYBOOKS:
        raise FileNotFoundError(f"Unsupported playbook: {playbook_name}")

    playbook_path = PLAYBOOKS_DIR / safe_name
    if not playbook_path.exists():
        raise FileNotFoundError(f"Playbook not found: {playbook_path}")

    with open(playbook_path, "r", encoding="utf-8") as f:
        return json.load(f)


def execute_playbook(
    playbook_name: str,
    incident_id: str,
    threat_context: str = None
) -> dict[str, Any]:
    """
    Execute a threat response playbook.

    Args:
        playbook_name: Name of the playbook (e.g. ransomware, ddos)
        incident_id: Unique identifier for this incident
        threat_context: Optional JSON string with threat details for logging

    Returns:
        Dict with execution results: actions_taken, status, timestamp, duration_ms
    """
    import json as _json
    start_time = time.time()
    context_dict = None
    if threat_context:
        if isinstance(threat_context, dict):
            context_dict = threat_context
        else:
            try:
                context_dict = _json.loads(threat_context)
            except Exception:
                context_dict = None

    try:
        playbook = _load_playbook(playbook_name)
    except FileNotFoundError:
        return {
            "status": "error",
            "message": f"Playbook '{playbook_name}' not found",
            "incident_id": incident_id,
            "actions_taken": []
        }

    # Safety must be enforced by the tool, not only by an LLM instruction.
    # A gated playbook cannot execute unless the dashboard recorded approval
    # for this exact incident ID.
    if playbook.get("requires_approval", False):
        from frontend.state import get_approval_result

        approval_status = get_approval_result(incident_id)
        if approval_status != "approved":
            return {
                "status": "blocked_approval_required",
                "playbook": playbook_name,
                "incident_id": incident_id,
                "approval_status": approval_status or "not_requested",
                "message": "Operator approval is required before this playbook can execute.",
                "actions_taken": [],
            }

    actions_taken = []
    execution_log = []

    for action in playbook.get("actions", []):
        action_name = action.get("action", "unknown")
        action_target = action.get("target", "")
        action_method = action.get("method", "")

        # Simulate action execution (in production these would call real APIs)
        result = _simulate_action(action_name, action_target, action_method)
        actions_taken.append({
            "action": action_name,
            "target": action_target,
            "method": action_method,
            "result": result,
            "timestamp": datetime.utcnow().isoformat()
        })
        execution_log.append(f"[{action_name}] {action_target} → {result}")

    duration_ms = int((time.time() - start_time) * 1000)

    return {
        "status": "executed",
        "playbook": playbook_name,
        "playbook_description": playbook.get("description", ""),
        "incident_id": incident_id,
        "actions_taken": actions_taken,
        "execution_log": execution_log,
        "duration_ms": duration_ms,
        "timestamp": datetime.utcnow().isoformat(),
        "recovery_steps": playbook.get("recovery_steps", []),
        "notify_targets": playbook.get("notify_targets", [])
    }


def _simulate_action(action: str, target: str, method: str) -> str:
    """
    Simulate execution of a playbook action.
    In production this would call real infrastructure APIs.
    """
    action_responses = {
        "isolate_node": f"Node {target} isolated from network — confirmed",
        "block_ip": f"IP {target} blocked via firewall rule — rule ID {hash(target) % 99999}",
        "alert_operator": f"Alert dispatched to {target} via {method}",
        "disable_account": f"Account {target} disabled — access revoked",
        "capture_forensics": f"Forensic snapshot of {target} captured to secure storage",
        "notify_soc": f"SOC notified via {method} — ticket opened",
        "rate_limit": f"Traffic from {target} rate-limited to 10% capacity",
        "enable_backup_isolation": f"Backup systems on {target} isolated from primary network",
        "revoke_tokens": f"All active tokens for {target} revoked",
        "quarantine_traffic": f"All traffic from {target} quarantined for inspection",
    }
    return action_responses.get(action, f"Action '{action}' executed on {target}")


async def request_human_approval(
    incident_id: str,
    threat_classification: str,
    threat_summary: str,
    ai_reasoning: str,
    recommended_playbook: str,
    mitre_techniques: list = None,
    cves: list = None,
    timeout_seconds: int = 120
) -> dict[str, Any]:
    """
    Request human approval before executing a CRITICAL threat response.
    Pushes an approval request to the dashboard and waits for operator input.

    Args:
        incident_id: Unique incident identifier
        threat_classification: CRITICAL or HIGH
        threat_summary: Plain-English description of the threat
        ai_reasoning: Full AI reasoning chain for the operator to review
        recommended_playbook: The playbook the agent wants to execute
        mitre_techniques: Matched MITRE techniques list
        cves: Relevant CVE IDs
        timeout_seconds: How long to wait before auto-escalating

    Returns:
        Dict with approval_status: approved, rejected, timeout, or escalated
    """
    import asyncio
    from frontend.state import clear_pending_approval, push_approval_request, get_approval_result

    approval_payload = {
        "incident_id": incident_id,
        "classification": threat_classification,
        "summary": threat_summary,
        "ai_reasoning": ai_reasoning,
        "recommended_playbook": recommended_playbook,
        "mitre_techniques": mitre_techniques or [],
        "cves": cves or [],
        "requested_at": datetime.utcnow().isoformat(),
        "timeout_seconds": timeout_seconds,
        "status": "pending"
    }

    # Push to dashboard state — frontend will render the approval modal
    push_approval_request(approval_payload)

    # Poll using async sleep so the FastAPI event loop stays unblocked
    # and WebSocket broadcasts keep flowing to the browser
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        result = get_approval_result(incident_id)
        if result in ("approved", "rejected", "escalated"):
            return {
                "approval_status": result,
                "incident_id": incident_id,
                "responded_at": datetime.utcnow().isoformat(),
                "waited_seconds": int(timeout_seconds - (deadline - time.time()))
            }
        await asyncio.sleep(2)

    # Timeout — escalate automatically
    clear_pending_approval(incident_id)
    return {
        "approval_status": "timeout",
        "incident_id": incident_id,
        "message": f"No operator response within {timeout_seconds}s — escalated to SOC",
        "action": "auto_escalated"
    }
