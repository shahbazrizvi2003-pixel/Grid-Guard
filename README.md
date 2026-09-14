#  GridGuard
### Autonomous Cyber Threat Response for Energy Grid Infrastructure
**Google Cloud Rapid Agent — Arize Phoenix MCP Track**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-green.svg)](https://python.org)
[![GCP](https://img.shields.io/badge/Deployed%20on-Cloud%20Run-blue.svg)](https://cloud.google.com/run)

> Energy grids are being attacked by AI. The AI defending them can't be trusted or explained. GridGuard fixes both.

---

## 🌐 Live Demo
**Dashboard:** `https://gridguard-xxxx-uc.a.run.app` *(URL after Cloud Run deploy)*  
**Demo Video:** *(YouTube link after recording)*  
**Arize Phoenix:** *(add the exact workspace/project link after Phoenix setup)*

---

##  Architecture

```
SCADA Telemetry Simulator (12 nodes)
         │
         ▼
┌─────────────────────────────────────┐
│   Google ADK SequentialAgent        │
│                                     │
│  [Detection Agent]                  │
│    → read_scada_telemetry           │
│    → check_voltage_anomaly          │
│    → check_access_patterns          │
│    → check_command_sequences        │
│         │ detection_result          │
│         ▼                           │
│  [Investigation Agent]              │
│    → lookup_mitre_technique (ICS)   │
│    → lookup_cve (NVD API)           │
│         │ investigation_result      │
│         ▼                           │
│  [Response Agent]                   │
│    → request_human_approval (CRIT)  │
│    → execute_playbook               │
│    → generate_incident_report       │
└─────────────────────────────────────┘
         │
         ▼
  Arize Phoenix (Full Tracing)
  + Hallucination Detection
  + Response Quality Scoring
         │
         ▼
  FastAPI Dashboard (Cloud Run)
  + WebSocket Real-Time Map
  + Human Approval Gate
  + Incident Report Viewer
```

---

## 🚀 Quick Start (Local)

### Prerequisites
- Python 3.11+
- Node.js 18+ (for Arize Phoenix MCP)
- GCP project with billing enabled

### 1. Clone & Install
```bash
git clone https://github.com/YOUR_USERNAME/gridguard.git
cd gridguard
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure Environment
```bash
cp .env.example .env
# Edit .env — set your GCP project, PHOENIX_API_KEY and NVD_API_KEY.
# GRIDGUARD_MODEL defaults to gemini-3-flash-preview and can be overridden.
```

### 3. Run Locally
```bash
python verify_pipeline.py
python main.py
# Dashboard: http://localhost:8080
```

Live integrations can be checked individually after ADC and Phoenix workspace
configuration:

```bash
python verify_integrations.py --nvd
python verify_integrations.py --phoenix-api --phoenix-mcp
python verify_integrations.py --gemini --attack ddos
```

There is no database or migration step. Incident state is intentionally
in-process for the single-instance demo and resets on restart. See
[`GCP_HANDOFF.md`](GCP_HANDOFF.md) for production setup and
[`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md) for verified phase status.

### 4. Inject a Live Attack
Open `http://localhost:8080` → click any attack button in the Demo Control Panel.  
Watch the agent pipeline execute in the Decision Timeline.

### Incident history and replay

Completed incidents include post-response grounding and playbook-quality checks.
Use the **Replay Decisions** button in an incident report, or query:

```text
GET /api/incidents
GET /api/incidents/{incident_id}/replay
GET /api/evaluations
```

---

## ☁️ Deploy to Cloud Run

```bash
# One-time GCP setup
bash deploy/gcp_setup.sh

# Deploy
bash deploy/deploy_cloudrun.sh

# Deploy the ADK orchestrator to Vertex AI Agent Engine
python deploy/deploy_agent_engine.py
```

Or submit the same build manually:
```bash
gcloud builds submit --config deploy/cloudbuild.yaml .
```

---

## 🧠 Arize Phoenix Integration

GridGuard traces every AI decision to Arize Phoenix:

| Span | What It Traces |
|------|---------------|
| `scada.read_telemetry` | Raw telemetry read with voltage, frequency, status |
| `detection.voltage_anomaly_check` | Deviation %, threshold comparison |
| `detection.access_pattern_check` | External IPs, suspicious actions found |
| `detection.command_sequence_check` | Dangerous SCADA commands matched |
| `investigation.mitre_lookup` | MITRE ICS technique IDs returned |
| `investigation.cve_lookup` | CVE IDs with CVSS scores |
| `gridguard.full_pipeline` | End-to-end incident trace |

**Hallucination Detection:** `HallucinationEvaluator` fires when agent references CVEs or MITRE techniques not returned by the lookup tools.

**Response Quality:** `RelevanceEvaluator` scores whether the chosen playbook matches the detected threat type.

---

## 🎯 Attack Scenarios

| Attack | Severity | Playbook | Approval Required |
|--------|----------|----------|-------------------|
| Ransomware | CRITICAL | ransomware.json | ✅ Yes |
| Unauthorized Access | HIGH | unauthorized_access.json | ✅ Yes |
| DDoS | HIGH | ddos.json | ❌ Auto |
| Data Exfiltration | HIGH | data_exfiltration.json | ❌ Auto |

---

## 📁 Project Structure

```
gridguard/
├── agents/          # ADK agent definitions
│   ├── orchestrator.py       # SequentialAgent pipeline
│   ├── detection_agent.py    # SCADA anomaly detection
│   ├── investigation_agent.py # MITRE + CVE correlation
│   ├── response_agent.py     # Playbook execution
│   └── pipeline_runner.py    # Async pipeline orchestration
├── tools/           # Agent tools (Phoenix-traced)
│   ├── scada_reader.py       # Telemetry reading + checks
│   ├── mitre_lookup.py       # MITRE ATT&CK ICS
│   ├── cve_lookup.py         # NVD CVE database
│   ├── playbook_executor.py  # Response execution
│   ├── report_generator.py   # Incident reports
│   └── secrets.py            # GCP Secret Manager
├── simulator/       # SCADA data simulation
│   ├── scada_simulator.py    # 12-node grid simulator
│   └── attack_scenarios.py   # 4 injectable attack types
├── playbooks/       # JSON response playbooks
├── observability/   # Arize Phoenix integration
│   ├── phoenix_setup.py      # OTel tracer init
│   └── evaluators.py         # Hallucination + quality
├── frontend/        # FastAPI dashboard
│   ├── main.py               # API + WebSocket
│   ├── state.py              # Shared in-memory state
│   └── static/               # HTML, CSS, JS
├── deploy/          # Dockerfile, Cloud Build, scripts
└── main.py          # Application entry point
```

---

## 🏆 Judging Criteria Coverage

| Criterion | Score | Evidence |
|-----------|-------|---------|
| Technical Implementation | Target: 9/10 | ADK SequentialAgent, Phoenix traces, Secret Manager and Cloud Run assets; live deployment remains |
| Design & UX | 8/10 | Real-time grid map, WebSocket timeline, human approval modal, incident reports |
| Potential Impact | 10/10 | Energy sector #4 most attacked globally, zero affordable AI-native solution |
| Quality of Idea | 10/10 | First system combining OT/SCADA autonomous response + LLM observability |

---

## 👥 Team
- **MLOps Engineer** — Arize Phoenix integration, evaluators, tracing
- **DevOps Engineer** — GCP, Cloud Run, Secret Manager, Dockerfile  
- **Systems Engineer** — SCADA simulator, data pipeline, FastAPI backend
- **Cyber Security Expert** — Attack scenarios, playbooks, MITRE mapping

---

## 📄 License
Apache 2.0 — See [LICENSE](LICENSE)

## 🔗 References
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)
- [NIST NVD API](https://nvd.nist.gov/developers/vulnerabilities)
- [Google ADK](https://google.github.io/adk-docs/)
- [Arize Phoenix](https://docs.arize.com/phoenix)
