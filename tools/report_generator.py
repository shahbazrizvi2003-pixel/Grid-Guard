"""
GridGuard — Incident Report Generator Tool
Generates plain-English incident reports after threat resolution.
Reports are stored in memory and served by the dashboard.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Any

# In-memory store of resolved incident reports (served to dashboard)
_incident_reports: list[dict] = []


def get_all_reports() -> list[dict]:
    """Return all generated incident reports (used by dashboard API)."""
    return list(reversed(_incident_reports))  # Most recent first


def generate_incident_report(
    incident_id: str,
    detection_result: str,
    investigation_result: str,
    response_result: str,
    approval_status: str = "not_required"
) -> dict[str, Any]:
    """
    Generate a plain-English incident report for a resolved threat.

    Args:
        incident_id: Unique incident identifier
        detection_result: JSON string output from detection agent
        investigation_result: JSON string output from investigation agent
        response_result: JSON string output from response agent
        approval_status: Whether human approved the response

    Returns:
        Structured incident report saved to memory and returned.
    """
    import json as _json

    def _parse(val):
        if isinstance(val, dict):
            return val
        try:
            return _json.loads(val) if val else {}
        except Exception:
            return {}

    detection_result = _parse(detection_result)
    investigation_result = _parse(investigation_result)
    response_result = _parse(response_result)

    now = datetime.now(timezone.utc)

    # Extract key data
    anomaly_type = detection_result.get("type", "unknown")
    node_id = detection_result.get("raw_data", {}).get("node_id", "UNKNOWN")
    confidence = detection_result.get("confidence", 0.0)

    classification = investigation_result.get("classification", "UNKNOWN")
    attack_type = investigation_result.get("attack_type", anomaly_type)
    mitre_techniques = investigation_result.get("mitre_techniques", [])
    cves = investigation_result.get("cves", [])
    false_positive_prob = investigation_result.get("false_positive_probability", 0.0)

    playbook_used = response_result.get("playbook", "unknown")
    actions_taken = response_result.get("actions_taken", [])
    execution_status = response_result.get("status", "unknown")

    # Build human-readable narrative
    narrative = _build_narrative(
        node_id=node_id,
        attack_type=attack_type,
        classification=classification,
        mitre_techniques=mitre_techniques,
        cves=cves,
        actions_taken=actions_taken,
        approval_status=approval_status,
        playbook_used=playbook_used
    )

    report = {
        "report_id": str(uuid.uuid4())[:8].upper(),
        "incident_id": incident_id,
        "generated_at": now.isoformat(),
        "title": f"{classification} {attack_type.replace('_', ' ').title()} Incident — {node_id}",

        # Summary
        "executive_summary": narrative["summary"],
        "what_happened": narrative["what_happened"],
        "what_agent_did": narrative["what_agent_did"],
        "why_agent_responded": narrative["why_agent_responded"],
        "outcome": narrative["outcome"],

        # Technical details
        "node_id": node_id,
        "attack_type": attack_type,
        "classification": classification,
        "agent_confidence": round(confidence, 2),
        "false_positive_probability": round(false_positive_prob, 2),

        # Threat intelligence
        "mitre_techniques": [
            {"id": t.get("technique_id", ""), "name": t.get("name", ""), "url": t.get("url", "")}
            for t in (mitre_techniques if isinstance(mitre_techniques, list) else [])
        ],
        "cves": [
            {"id": c.get("id", ""), "cvss_score": c.get("cvss_score"), "severity": c.get("severity", "")}
            for c in (cves if isinstance(cves, list) else [])
        ],

        # Response
        "playbook_executed": playbook_used,
        "actions_count": len(actions_taken),
        "actions_taken": [a.get("action", "") if isinstance(a, dict) else str(a) for a in actions_taken],
        "human_approval": approval_status,
        "execution_status": execution_status,

        # Metadata
        "severity_badge": _severity_badge(classification),
        "status": "resolved"
    }

    # Store for dashboard
    _incident_reports.append(report)

    # Cap memory store at 50 most recent reports
    if len(_incident_reports) > 50:
        _incident_reports.pop(0)

    return report


def _build_narrative(
    node_id: str,
    attack_type: str,
    classification: str,
    mitre_techniques: list,
    cves: list,
    actions_taken: list,
    approval_status: str,
    playbook_used: str
) -> dict[str, str]:
    """Build the plain-English narrative sections of the report."""

    attack_readable = attack_type.replace("_", " ")
    technique_names = [
        t.get("name", t.get("technique_id", ""))
        for t in (mitre_techniques if isinstance(mitre_techniques, list) else [])
    ][:2]
    cve_ids = [c.get("id", "") for c in (cves if isinstance(cves, list) else [])][:2]
    action_names = [a.get("action", "") if isinstance(a, dict) else str(a) for a in actions_taken][:3]

    summary = (
        f"A {classification} {attack_readable} attack was detected on grid node {node_id}. "
        f"The GridGuard autonomous agent responded within seconds, executing the {playbook_used} playbook."
    )

    what_happened = (
        f"Anomalous SCADA telemetry was detected on node {node_id} indicating a {attack_readable} attack. "
        + (f"The activity matched MITRE ATT&CK ICS techniques {', '.join(technique_names)}. " if technique_names else "")
        + (f"Relevant vulnerabilities include {', '.join(cve_ids)}." if cve_ids else "")
    )

    what_agent_did = (
        f"The GridGuard agent automatically: "
        + ", ".join(action_names)
        + (f" (after operator approval)" if approval_status == "approved" else "")
        + "."
    ) if action_names else "The agent logged the incident and generated this report."

    why_agent_responded = (
        f"The threat was classified as {classification} based on MITRE ICS technique mapping "
        f"and correlation with known SCADA vulnerabilities. "
        + (f"Human approval was obtained before execution because this was a {classification} threat." 
           if approval_status == "approved" else
           f"Autonomous execution was performed as this threat level does not require human approval.")
    )

    outcome = (
        f"The {attack_readable} threat on {node_id} has been contained. "
        f"The {playbook_used} response playbook executed successfully. "
        f"All affected systems have been flagged for post-incident review."
    )

    return {
        "summary": summary,
        "what_happened": what_happened,
        "what_agent_did": what_agent_did,
        "why_agent_responded": why_agent_responded,
        "outcome": outcome
    }


def _severity_badge(classification: str) -> str:
    badges = {
        "CRITICAL": "🔴 CRITICAL",
        "HIGH": "🟠 HIGH",
        "MEDIUM": "🟡 MEDIUM",
        "LOW": "🟢 LOW"
    }
    return badges.get(classification.upper(), "⚪ UNKNOWN")
