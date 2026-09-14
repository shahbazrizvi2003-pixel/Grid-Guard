"""
GridGuard — SCADA Reader Tools
Tools called by the Detection Agent to read and analyze SCADA telemetry.
Each function is a tool the LLM agent can invoke.
All tool calls are traced to Arize Phoenix via custom spans.
"""

from datetime import datetime
from typing import Any
from opentelemetry import trace

# Get the gridguard tracer — initialized by observability/phoenix_setup.py
_tracer = trace.get_tracer("gridguard.scada_reader")

# Shared in-memory state — the simulator writes here, agents read from here
_current_telemetry: dict = {}
_active_attack: str | None = None


def set_telemetry(data: dict, attack_type: str | None = None) -> None:
    """Called by the simulator to push live telemetry into the reader."""
    global _current_telemetry, _active_attack
    _current_telemetry = data
    _active_attack = attack_type


def read_scada_telemetry(telemetry_snapshot: str = None) -> dict[str, Any]:
    """
    Read the current SCADA telemetry snapshot from the energy grid.

    Args:
        telemetry_snapshot: Optional JSON string of mission-provided reading.
            Pass the full telemetry JSON as a string. This supports remote
            Agent Engine calls where no local simulator process exists.

    Returns a JSON object with:
    - timestamp, node_id, voltage (V), frequency (Hz), current (A)
    - access_log: list of recent access events
    - command_log: list of recent SCADA commands issued
    - status: NORMAL | ANOMALY
    """
    import json as _json
    with _tracer.start_as_current_span("scada.read_telemetry") as span:
        snapshot_dict = None
        if telemetry_snapshot:
            if isinstance(telemetry_snapshot, dict):
                snapshot_dict = telemetry_snapshot
            else:
                try:
                    snapshot_dict = _json.loads(telemetry_snapshot)
                except Exception:
                    snapshot_dict = None
        if snapshot_dict:
            reading = dict(snapshot_dict)
            set_telemetry(reading, reading.get("attack_type"))
        elif not _current_telemetry:
            reading = {
                "timestamp": datetime.utcnow().isoformat(),
                "node_id": "SUBSTATION_001",
                "voltage": 230.0,
                "frequency": 50.0,
                "current": 45.0,
                "access_log": [],
                "command_log": [],
                "status": "NORMAL",
                "source": "default_no_data"
            }
        else:
            reading = dict(_current_telemetry)

        span.set_attribute("scada.node_id", reading.get("node_id", "UNKNOWN"))
        span.set_attribute("scada.voltage", reading.get("voltage", 0))
        span.set_attribute("scada.frequency", reading.get("frequency", 0))
        span.set_attribute("scada.status", reading.get("status", "UNKNOWN"))
        span.set_attribute("scada.attack_type", str(reading.get("attack_type", "none")))
        span.set_attribute("scada.command_count", len(reading.get("command_log", [])))
        span.set_attribute("scada.access_count", len(reading.get("access_log", [])))
        return reading


def check_voltage_anomaly() -> dict[str, Any]:
    """
    Analyze voltage readings for anomalies.

    Normal range: 218V – 242V (230V ±5%)
    Returns anomaly flag, current value, deviation percentage, and severity.
    """
    with _tracer.start_as_current_span("detection.voltage_anomaly_check") as span:
        telemetry = read_scada_telemetry()
        voltage = telemetry.get("voltage", 230.0)
        node_id = telemetry.get("node_id", "UNKNOWN")

        NORMAL_MIN = 218.0
        NORMAL_MAX = 242.0
        nominal = 230.0
        deviation_pct = abs(voltage - nominal) / nominal * 100

        span.set_attribute("check.node_id", node_id)
        span.set_attribute("check.voltage", voltage)
        span.set_attribute("check.deviation_pct", round(deviation_pct, 2))
        span.set_attribute("check.normal_min", NORMAL_MIN)
        span.set_attribute("check.normal_max", NORMAL_MAX)

        if voltage < NORMAL_MIN or voltage > NORMAL_MAX:
            severity = "CRITICAL" if deviation_pct > 15 else "HIGH"
            result = {
                "anomaly_detected": True,
                "type": "voltage_anomaly",
                "node_id": node_id,
                "current_voltage": voltage,
                "normal_range": [NORMAL_MIN, NORMAL_MAX],
                "deviation_percent": round(deviation_pct, 2),
                "severity": severity,
                "message": f"Voltage {voltage:.1f}V is {deviation_pct:.1f}% outside normal range"
            }
            span.set_attribute("check.anomaly_detected", True)
            span.set_attribute("check.severity", severity)
            return result

        span.set_attribute("check.anomaly_detected", False)
        return {
            "anomaly_detected": False,
            "node_id": node_id,
            "current_voltage": voltage,
            "deviation_percent": round(deviation_pct, 2)
        }


def check_access_patterns() -> dict[str, Any]:
    """
    Analyze access logs for suspicious patterns.

    Flags: foreign IPs, failed auth attempts, privilege escalation,
    off-hours access, and unusual geographic origins.
    Returns anomaly flag with details of suspicious events.
    """
    with _tracer.start_as_current_span("detection.access_pattern_check") as span:
        telemetry = read_scada_telemetry()
        access_log = telemetry.get("access_log", [])
        node_id = telemetry.get("node_id", "UNKNOWN")

        suspicious_events = []
        severity = "NORMAL"

        KNOWN_INTERNAL_IP_PREFIXES = ["10.", "192.168.", "172.16."]
        SUSPICIOUS_ACTIONS = [
            "PRIVILEGE_ESCALATION", "FAILED_AUTH", "FOREIGN_IP_ACCESS",
            "ROOT_LOGIN", "UNAUTHORIZED_EXPORT"
        ]

        span.set_attribute("check.node_id", node_id)
        span.set_attribute("check.access_events_total", len(access_log))

        for event in access_log:
            ip = event.get("source_ip", "")
            action = event.get("action", "")
            is_internal = any(ip.startswith(p) for p in KNOWN_INTERNAL_IP_PREFIXES)

            if not is_internal and ip:
                suspicious_events.append({
                    "type": "external_ip_access", "ip": ip,
                    "action": action, "timestamp": event.get("timestamp", "")
                })
                severity = "HIGH"

            if action in SUSPICIOUS_ACTIONS:
                suspicious_events.append({
                    "type": "suspicious_action", "action": action,
                    "ip": ip, "timestamp": event.get("timestamp", "")
                })
                severity = "CRITICAL" if action == "PRIVILEGE_ESCALATION" else "HIGH"

        span.set_attribute("check.suspicious_events_found", len(suspicious_events))
        span.set_attribute("check.anomaly_detected", len(suspicious_events) > 0)
        span.set_attribute("check.severity", severity)

        if suspicious_events:
            return {
                "anomaly_detected": True,
                "type": "access_anomaly",
                "node_id": node_id,
                "suspicious_events": suspicious_events,
                "event_count": len(suspicious_events),
                "severity": severity
            }
        return {
            "anomaly_detected": False,
            "node_id": node_id,
            "access_events_checked": len(access_log)
        }


def check_command_sequences() -> dict[str, Any]:
    """
    Analyze SCADA command logs for unauthorized or dangerous sequences.

    Flags: encrypt commands, backup disabling, unusual remote commands,
    shutdown sequences, data export commands.
    Returns anomaly flag with matched dangerous patterns.
    """
    with _tracer.start_as_current_span("detection.command_sequence_check") as span:
        telemetry = read_scada_telemetry()
        command_log = telemetry.get("command_log", [])
        node_id = telemetry.get("node_id", "UNKNOWN")

        DANGEROUS_COMMANDS = {
            "ENCRYPT_FILES": "ransomware_indicator",
            "DISABLE_BACKUP": "ransomware_indicator",
            "MASS_READ": "data_exfiltration_indicator",
            "BULK_EXPORT": "data_exfiltration_indicator",
            "REMOTE_SHUTDOWN": "sabotage_indicator",
            "OVERRIDE_SAFETY": "sabotage_indicator",
            "FLOOD_PING": "ddos_indicator",
            "PORT_SCAN": "reconnaissance_indicator",
        }

        matched = []
        attack_indicators: set[str] = set()

        span.set_attribute("check.node_id", node_id)
        span.set_attribute("check.commands_total", len(command_log))

        for cmd in command_log:
            cmd_upper = cmd.upper() if isinstance(cmd, str) else cmd.get("command", "").upper()
            # Strip colon-suffixed commands (e.g. "FLOOD_PING:broadcast" → "FLOOD_PING")
            cmd_key = cmd_upper.split(":")[0]
            if cmd_key in DANGEROUS_COMMANDS:
                indicator = DANGEROUS_COMMANDS[cmd_key]
                matched.append({"command": cmd_key, "indicator": indicator})
                attack_indicators.add(indicator)

        span.set_attribute("check.dangerous_commands_found", len(matched))
        span.set_attribute("check.attack_indicators", str(list(attack_indicators)))
        span.set_attribute("check.anomaly_detected", len(matched) > 0)

        if matched:
            severity = "CRITICAL" if "ransomware_indicator" in attack_indicators else "HIGH"
            span.set_attribute("check.severity", severity)
            return {
                "anomaly_detected": True,
                "type": "command_sequence_anomaly",
                "node_id": node_id,
                "dangerous_commands": matched,
                "attack_indicators": list(attack_indicators),
                "severity": severity,
                "message": f"Detected {len(matched)} dangerous command(s): {[m['command'] for m in matched]}"
            }

        span.set_attribute("check.severity", "NONE")
        return {
            "anomaly_detected": False,
            "node_id": node_id,
            "commands_checked": len(command_log)
        }
