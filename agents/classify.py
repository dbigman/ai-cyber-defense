"""Classify Agent — scores risk, enriches context, correlates events."""

import json
import os
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from tools.classification_tools import risk_scorer, context_enricher, event_correlator


CLASSIFY_SYSTEM_PROMPT = """You are a Threat Classification Agent. Your job is to:
1. Score each threat for risk severity using the risk_scorer tool
2. Enrich findings with MITRE ATT&CK context using the context_enricher tool
3. Correlate related findings into incident groups using the event_correlator tool

Run all three tools in sequence, passing output from each to the next.
Provide a brief summary of the most critical findings."""


def create_classify_agent(model_name: str = "deepseek-chat"):
    llm = ChatOpenAI(
        model=model_name,
        temperature=0,
        api_key=os.environ.get("DEEPSEEK_API_KEY"),
        base_url="https://api.deepseek.com",
    )
    return create_react_agent(
        llm,
        tools=[risk_scorer, context_enricher, event_correlator],
        prompt=CLASSIFY_SYSTEM_PROMPT,
    )


def run_classify(state: dict, model_name: str = "gpt-4o-mini") -> dict:
    """Classify threats: score → enrich → correlate (deterministic tool chain)."""
    threats_json = json.dumps({"threats": state["threats"]})

    # Step 1: Risk scoring
    scored_result = json.loads(risk_scorer.invoke(threats_json))
    scored_threats = scored_result.get("classifications", scored_result.get("scored_threats", []))

    # Step 2: Enrich with MITRE ATT&CK context
    enriched_result = json.loads(context_enricher.invoke(json.dumps({"classifications": scored_threats})))
    enriched_threats = enriched_result.get("enriched_classifications", enriched_result.get("enriched_threats", []))

    # Step 3: Correlate into incidents
    correlated_result = json.loads(event_correlator.invoke(json.dumps({"enriched_classifications": enriched_threats})))
    classifications = correlated_result.get("incidents", correlated_result.get("correlated_incidents", []))

    reasoning = (
        f"Scored {len(scored_threats)} threats. "
        f"Enriched with MITRE ATT&CK context. "
        f"Correlated into {len(classifications)} incident groups."
    )

    state["classifications"] = classifications
    state["agent_reasoning"] = state.get("agent_reasoning", {})
    state["agent_reasoning"]["classify"] = reasoning
    return state
