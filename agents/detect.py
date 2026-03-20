"""Detect Agent — scans normalized events for threats and anomalies."""

import json
import os
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from tools.detection_tools import pattern_detector, anomaly_detector, threat_lookup


DETECT_SYSTEM_PROMPT = """You are a Threat Detection Agent. Your job is to analyze normalized security events for threats.

Run ALL three detection tools on the events:
1. pattern_detector — finds brute force, credential stuffing, port scans, privilege escalation
2. anomaly_detector — finds statistical anomalies (off-hours logins, geo-anomalies, volume spikes)
3. threat_lookup — checks IPs against known threat intelligence

Pass the full events JSON to each tool. Combine all results and summarize what you found."""


def create_detect_agent(model_name: str = "deepseek-chat"):
    llm = ChatOpenAI(
        model=model_name,
        temperature=0,
        api_key=os.environ.get("DEEPSEEK_API_KEY"),
        base_url="https://api.deepseek.com",
    )
    return create_react_agent(
        llm,
        tools=[pattern_detector, anomaly_detector, threat_lookup],
        prompt=DETECT_SYSTEM_PROMPT,
    )


def run_detect(state: dict, model_name: str = "gpt-4o-mini") -> dict:
    """Run all three detection tools directly on normalized events."""
    events_json = json.dumps({"normalized_events": state["normalized_events"]})

    # Run all 3 detectors
    pattern_result = json.loads(pattern_detector.invoke(events_json))
    anomaly_result = json.loads(anomaly_detector.invoke(events_json))
    threat_result = json.loads(threat_lookup.invoke(events_json))

    all_threats = []
    all_threats.extend(pattern_result.get("threats", []))
    all_threats.extend(anomaly_result.get("anomalies", []))
    all_threats.extend(threat_result.get("threat_intel_hits", []))

    reasoning = (
        f"Pattern Detector: {pattern_result.get('threat_count', 0)} threats. "
        f"Anomaly Detector: {anomaly_result.get('anomaly_count', 0)} anomalies. "
        f"Threat Intel: {threat_result.get('hits_count', 0)} hits from {threat_result.get('ips_checked', 0)} IPs checked."
    )

    state["threats"] = all_threats
    state["agent_reasoning"] = state.get("agent_reasoning", {})
    state["agent_reasoning"]["detect"] = reasoning
    return state
