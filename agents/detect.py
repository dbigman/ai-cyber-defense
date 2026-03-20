"""Detect Agent — scans normalized events for threats and anomalies."""

import json
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from tools.detection_tools import pattern_detector, anomaly_detector, threat_lookup


DETECT_SYSTEM_PROMPT = """You are a Threat Detection Agent. Your job is to analyze normalized security events for threats.

Run ALL three detection tools on the events:
1. pattern_detector — finds brute force, credential stuffing, port scans, privilege escalation
2. anomaly_detector — finds statistical anomalies (off-hours logins, geo-anomalies, volume spikes)
3. threat_lookup — checks IPs against known threat intelligence

Pass the full events JSON to each tool. Combine all results and summarize what you found."""


def create_detect_agent(model_name: str = "gpt-4o-mini"):
    llm = ChatOpenAI(model=model_name, temperature=0)
    return create_react_agent(
        llm,
        tools=[pattern_detector, anomaly_detector, threat_lookup],
        prompt=DETECT_SYSTEM_PROMPT,
    )


def run_detect(state: dict, model_name: str = "gpt-4o-mini") -> dict:
    """Run detection on normalized events and update state with threats."""
    agent = create_detect_agent(model_name)
    events_json = json.dumps({"normalized_events": state["normalized_events"]})

    result = agent.invoke({
        "messages": [
            {"role": "user", "content": f"Analyze these normalized security events for threats and anomalies:\n\n{events_json}"}
        ]
    })

    # Collect all threats from tool outputs
    all_threats = []
    reasoning = ""
    for msg in result["messages"]:
        if hasattr(msg, "content") and isinstance(msg.content, str):
            try:
                data = json.loads(msg.content)
                if "threats" in data:
                    all_threats.extend(data["threats"])
                if "anomalies" in data:
                    all_threats.extend(data["anomalies"])
                if "threat_intel_hits" in data:
                    all_threats.extend(data["threat_intel_hits"])
            except (json.JSONDecodeError, TypeError):
                pass
            if hasattr(msg, "type") and msg.type == "ai":
                reasoning += msg.content + "\n"

    state["threats"] = all_threats
    state["agent_reasoning"] = state.get("agent_reasoning", {})
    state["agent_reasoning"]["detect"] = reasoning.strip()
    return state
