"""
GridGuard — MITRE ATT&CK ICS Lookup Tool
Queries the public MITRE ATT&CK for ICS dataset (no API key required).
Fetches from GitHub-hosted STIX JSON, caches locally to avoid re-fetching.
All lookups traced to Arize Phoenix.
"""

import json
import os
import requests
from pathlib import Path
from typing import Any
from opentelemetry import trace

_tracer = trace.get_tracer("gridguard.mitre_lookup")

# Cache the MITRE ICS dataset locally after first fetch
CACHE_PATH = Path(__file__).parent.parent / "observability" / "mitre_ics_cache.json"
MITRE_ICS_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json"
)

# Maps GridGuard attack types to MITRE ICS tactic names
ATTACK_TYPE_TO_TACTIC: dict[str, str] = {
    "ransomware": "inhibit-response-function",
    "unauthorized_access": "initial-access",
    "ddos": "impact",
    "data_exfiltration": "collection",
}

# Curated fallback techniques for each attack type (used if API unavailable)
FALLBACK_TECHNIQUES: dict[str, list[dict]] = {
    "ransomware": [
        {
            "technique_id": "T0803",
            "name": "Block Command Message",
            "tactic": "inhibit-response-function",
            "description": "Adversaries block command messages to prevent operator control of field devices.",
            "url": "https://attack.mitre.org/techniques/T0803/"
        },
        {
            "technique_id": "T0809",
            "name": "Data Destruction",
            "tactic": "inhibit-response-function",
            "description": "Adversaries destroy data and files to interrupt availability of control systems.",
            "url": "https://attack.mitre.org/techniques/T0809/"
        }
    ],
    "unauthorized_access": [
        {
            "technique_id": "T0886",
            "name": "Remote Services",
            "tactic": "initial-access",
            "description": "Adversaries use remote services to initially access and persist within ICS networks.",
            "url": "https://attack.mitre.org/techniques/T0886/"
        },
        {
            "technique_id": "T0822",
            "name": "External Remote Services",
            "tactic": "initial-access",
            "description": "Adversaries leverage external-facing remote services to initially access ICS networks.",
            "url": "https://attack.mitre.org/techniques/T0822/"
        }
    ],
    "ddos": [
        {
            "technique_id": "T0814",
            "name": "Denial of Service",
            "tactic": "impact",
            "description": "Adversaries cause a denial of service (DoS) to disrupt operations or block operator response.",
            "url": "https://attack.mitre.org/techniques/T0814/"
        }
    ],
    "data_exfiltration": [
        {
            "technique_id": "T0868",
            "name": "Detect Operating Mode",
            "tactic": "collection",
            "description": "Adversaries collect target information to understand the current mode of operation.",
            "url": "https://attack.mitre.org/techniques/T0868/"
        },
        {
            "technique_id": "T0852",
            "name": "Screen Capture",
            "tactic": "collection",
            "description": "Adversaries capture screen output to gather information about ICS processes.",
            "url": "https://attack.mitre.org/techniques/T0852/"
        }
    ]
}


_CACHE_TTL_DAYS = 7


def _load_mitre_cache() -> dict | None:
    """Load cached MITRE STIX data from disk, invalidating if older than 7 days."""
    if CACHE_PATH.exists():
        import time as _time
        age_days = (_time.time() - CACHE_PATH.stat().st_mtime) / 86400
        if age_days > _CACHE_TTL_DAYS:
            print(f"[mitre_lookup] Cache expired ({age_days:.1f} days old) — refreshing")
            CACHE_PATH.unlink(missing_ok=True)
            return None
        try:
            with open(CACHE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
    return None


def _save_mitre_cache(data: dict) -> None:
    """Save MITRE STIX data to disk cache."""
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception:
        pass  # Cache write failure is non-fatal


def _fetch_mitre_stix() -> dict | None:
    """Fetch the MITRE ATT&CK ICS STIX bundle from GitHub."""
    cached = _load_mitre_cache()
    if cached:
        return cached

    try:
        resp = requests.get(MITRE_ICS_STIX_URL, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        _save_mitre_cache(data)
        return data
    except Exception as e:
        print(f"[mitre_lookup] Failed to fetch MITRE STIX data: {e}")
        return None


def _parse_techniques_from_stix(stix_bundle: dict, tactic_filter: str) -> list[dict]:
    """
    Parse STIX bundle and extract techniques matching the tactic filter.
    Returns a list of simplified technique objects.
    """
    techniques = []

    for obj in stix_bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        # Get tactic names from kill_chain_phases
        tactics = [
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-ics-attack"
        ]

        if tactic_filter not in tactics:
            continue

        # Extract technique ID from external references
        technique_id = ""
        url = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-ics-attack":
                technique_id = ref.get("external_id", "")
                url = ref.get("url", "")
                break

        if not technique_id:
            continue

        techniques.append({
            "technique_id": technique_id,
            "name": obj.get("name", ""),
            "tactic": tactic_filter,
            "description": obj.get("description", "")[:300],  # Truncate for tokens
            "url": url
        })

        if len(techniques) >= 3:  # Cap at 3 per lookup to control token usage
            break

    return techniques


def lookup_mitre_technique(anomaly_type: str) -> dict[str, Any]:
    """
    Look up MITRE ATT&CK ICS techniques for a detected anomaly type.

    Args:
        anomaly_type: One of 'ransomware', 'unauthorized_access', 'ddos', 'data_exfiltration'

    Returns:
        Dict with matching MITRE techniques, tactic name, source, and confidence score.
    """
    with _tracer.start_as_current_span("investigation.mitre_lookup") as span:
        tactic = ATTACK_TYPE_TO_TACTIC.get(anomaly_type.lower(), "impact")

        span.set_attribute("mitre.anomaly_type", anomaly_type)
        span.set_attribute("mitre.tactic_queried", tactic)
        span.set_attribute("input.value", f"anomaly_type={anomaly_type}")

        # Try live STIX data first
        stix_bundle = _fetch_mitre_stix()
        if stix_bundle:
            techniques = _parse_techniques_from_stix(stix_bundle, tactic)
            if techniques:
                span.set_attribute("mitre.source", "live")
                span.set_attribute("mitre.techniques_found", len(techniques))
                span.set_attribute("mitre.technique_ids",
                    str([t["technique_id"] for t in techniques]))
                span.set_attribute("output.value",
                    str([t["technique_id"] for t in techniques]))
                span.set_attribute("mitre.confidence", 0.92)

                return {
                    "techniques": techniques,
                    "tactic": tactic,
                    "anomaly_type": anomaly_type,
                    "source": "mitre_live",
                    "confidence": 0.92,
                    "technique_count": len(techniques)
                }

        # Fall back to curated dataset
        fallback = FALLBACK_TECHNIQUES.get(anomaly_type.lower(), [])
        span.set_attribute("mitre.source", "fallback")
        span.set_attribute("mitre.techniques_found", len(fallback))
        span.set_attribute("mitre.technique_ids",
            str([t["technique_id"] for t in fallback]))
        span.set_attribute("output.value",
            str([t["technique_id"] for t in fallback]))
        span.set_attribute("mitre.confidence", 0.85)

        return {
            "techniques": fallback,
            "tactic": tactic,
            "anomaly_type": anomaly_type,
            "source": "mitre_fallback",
            "confidence": 0.85,
            "technique_count": len(fallback)
        }
