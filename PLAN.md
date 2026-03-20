# AI Cyber Defense Multi-Agent System

## Overview
A LangGraph-based multi-agent system for analyzing security logs, detecting threats, classifying risk levels, and generating incident reports — with a live Gradio dashboard.

Based on the SMART COMPASS framework from the tutorial.

## Architecture

```
Security Logs → [Ingest Agent] → [Detect Agent] → [Classify Agent] → [Report Agent] → Dashboard
                     ↓                  ↓                 ↓                 ↓
               Validate data     Find threats      Assess risk      Generate report
               Parse logs        Anomaly detect    Enrich context   Action plans
```

## Agent Pipeline

### 1. Ingest Agent
- Parses raw security log files (CSV, JSON, syslog)
- Validates data quality (missing fields, malformed entries)
- Normalizes timestamps, IPs, event types
- Tools: `parse_log`, `validate_entry`, `normalize_data`

### 2. Detect Agent
- Scans normalized events for threats and anomalies
- Pattern matching (brute force, credential stuffing, port scanning)
- Statistical anomaly detection (unusual login times, geo-anomalies)
- Tools: `pattern_detector`, `anomaly_detector`, `threat_lookup`

### 3. Classify Agent
- Assesses severity: Critical / High / Medium / Low
- Enriches findings with context (known threat IPs, CVE references)
- Correlates related events
- Tools: `risk_scorer`, `context_enricher`, `event_correlator`

### 4. Report Agent
- Generates structured incident reports (Markdown)
- Groups similar findings, includes counts
- Recommends immediate/urgent/general actions
- Tools: `report_generator`, `action_recommender`

## Tech Stack

- **Python 3.11+**
- **LangGraph** — Multi-agent orchestration with state graph
- **LangChain** — LLM integration and tool framework
- **OpenAI GPT-4o-mini** — LLM (fast, cheap, good enough)
- **Gradio** — Live dashboard UI
- **MemorySaver** — Checkpointing for agent state persistence

## File Structure

```
ai-cyber-defense/
├── PLAN.md
├── README.md
├── requirements.txt
├── .env.example
├── run.py                    # Main entry point
├── dashboard.py              # Gradio UI
├── agents/
│   ├── __init__.py
│   ├── state.py              # AgentState definition
│   ├── graph.py              # LangGraph state graph builder
│   ├── ingest.py             # Ingest agent + tools
│   ├── detect.py             # Detect agent + tools
│   ├── classify.py           # Classify agent + tools
│   └── report.py             # Report agent + tools
├── tools/
│   ├── __init__.py
│   ├── ingestion_tools.py    # Log parsing, validation
│   ├── detection_tools.py    # Pattern/anomaly detection
│   ├── classification_tools.py  # Risk scoring, enrichment
│   └── report_tools.py      # Report generation
├── data/
│   └── sample_security_logs.json  # Sample data for testing
└── output/
    └── (generated reports)
```

## Sample Security Log Format

```json
{
  "timestamp": "2026-03-20T05:30:00Z",
  "source_ip": "192.168.1.100",
  "destination_ip": "10.0.0.5",
  "event_type": "login_attempt",
  "user": "admin",
  "status": "failed",
  "message": "Failed SSH login attempt",
  "port": 22,
  "protocol": "SSH"
}
```

## Dashboard Features (Gradio)

- File upload for security logs
- Agent reasoning toggle (show/hide)
- Model selector (GPT-4o-mini, etc.)
- Severity breakdown chart
- Detailed findings table
- Downloadable Markdown report
- Agent confidence scores

## Environment Variables

```
OPENAI_API_KEY=sk-...
```

## Running

```bash
# Install
pip install -r requirements.txt

# Run analysis (CLI)
python run.py --input data/sample_security_logs.json --output output/report.md

# Run dashboard
python dashboard.py
# Opens at http://localhost:7860
```
