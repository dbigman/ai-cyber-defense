"""Classify Agent — scores risk, enriches context, correlates events."""

import json
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from tools.classification_tools import risk_scorer, context_enricher, event_correlator


CLASSIFY_SYSTEM_PROMPT = """You are a Threat Classification Agent. Your job is to:
1. Score each threat for risk severity using the risk_scorer tool
2. Enrich findings with MITRE ATT&CK context using the context_enricher tool
3. Correlate related findings into incident groups using the event_correlator tool

Run all three tools in sequence, passing output from each to the next.
Provide a brief summary of the most critical findings."""


def create_classify_agent(model_name: str = "gpt-4o-mini"):
    llm = ChatOpenAI(model=model_name, temperature=0)
    return create_react_agent(
        llm,
        tools=[risk_scorer, context_enricher, event_correlator],
        prompt=CLASSIFY_SYSTEM_PROMPT,
    )


def run_classify(state: dict, model_name: str = "gpt-4o-mini") -> dict:
    """Classify threats and update state with classifications."""
    agent = create_classify_agent(model_name)
    threats_json = json.dumps({"threats": state["threats"]})

    result = agent.invoke({
        "messages": [
            {"role": "user", "content": f"Score, enrich, and correlate these security threats:\n\n{threats_json}"}
        ]
    })

    # Extract correlated incidents
    classifications = []
    reasoning = ""
    for msg in result["messages"]:
        if hasattr(msg, "content") and isinstance(msg.content, str):
            try:
                data = json.loads(msg.content)
                if "incidents" in data:
                    classifications = data["incidents"]
                elif "enriched_classifications" in data:
                    classifications = data["enriched_classifications"]
                elif "classifications" in data:
                    classifications = data["classifications"]
            except (json.JSONDecodeError, TypeError):
                pass
            if hasattr(msg, "type") and msg.type == "ai":
                reasoning += msg.content + "\n"

    state["classifications"] = classifications
    state["agent_reasoning"] = state.get("agent_reasoning", {})
    state["agent_reasoning"]["classify"] = reasoning.strip()
    return state
