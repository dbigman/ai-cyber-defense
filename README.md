# AI Cyber Defense Multi-Agent System

A LangGraph-based multi-agent pipeline for analyzing security logs, detecting threats, classifying risk, and generating incident reports — with a live Gradio dashboard.

## Architecture

```
Security Logs → [Ingest Agent] → [Detect Agent] → [Classify Agent] → [Report Agent] → Dashboard
                     ↓                  ↓                 ↓                 ↓
               Parse/validate     Pattern match      Risk scoring     Incident report
               Normalize          Anomaly detect     MITRE mapping    Action plans
                                  Threat intel       Correlation
```

**Conditional routing:** Detect → Classify only if threats are found. Classify → Report only if risk threshold is met.

## Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure API key
cp .env.example .env
# Edit .env and add your OpenAI API key

# 3. Run CLI analysis
python run.py --input data/sample_security_logs.json --output output/report.md

# 4. Run Gradio dashboard
python dashboard.py
# Opens at http://localhost:7860
```

## Detection Capabilities

| Category | Detections |
|----------|-----------|
| **Pattern Matching** | Brute force, credential stuffing, port scanning, privilege escalation, known attack tools |
| **Anomaly Detection** | Off-hours logins, geographic anomalies, impossible travel, volume spikes, rare critical events |
| **Threat Intelligence** | Known malicious IP lookup |
| **Classification** | MITRE ATT&CK mapping, CVE references, risk scoring (1-10), event correlation |

## Sample Data

`data/sample_security_logs.json` contains 36 events including:
- SSH brute force from known malicious IP (6 attempts)
- Credential stuffing targeting multiple users
- Port scan across 8 ports
- Privilege escalation via suspicious script
- Off-hours login from external IP with sensitive file access
- SQL injection and directory traversal (sqlmap/nikto)
- Normal business-hours activity (baseline)

## File Structure

```
├── run.py                 # CLI entry point
├── dashboard.py           # Gradio dashboard
├── agents/
│   ├── state.py           # AgentState TypedDict
│   ├── graph.py           # LangGraph pipeline with conditional edges
│   ├── ingest.py          # Log parsing/validation agent
│   ├── detect.py          # Threat detection agent
│   ├── classify.py        # Risk classification agent
│   └── report.py          # Report generation agent
├── tools/
│   ├── ingestion_tools.py # parse_log, validate_entry, normalize_data
│   ├── detection_tools.py # pattern_detector, anomaly_detector, threat_lookup
│   ├── classification_tools.py # risk_scorer, context_enricher, event_correlator
│   └── report_tools.py    # report_generator, action_recommender
└── data/
    └── sample_security_logs.json
```

## Tech Stack

- **LangGraph** — Multi-agent orchestration with state graph
- **LangChain** — LLM tool framework
- **OpenAI GPT-4o-mini** — Default LLM (fast, cost-effective)
- **Gradio** — Interactive dashboard
