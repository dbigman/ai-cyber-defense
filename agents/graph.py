"""LangGraph StateGraph connecting all 4 agents with conditional routing."""

import json
import time
from langgraph.graph import StateGraph, END

from agents.state import AgentState
from agents.ingest import run_ingest
from agents.detect import run_detect
from agents.classify import run_classify
from agents.report import run_report


def ingest_node(state: AgentState) -> AgentState:
    model = state.get("metadata", {}).get("model_name", "deepseek-chat")
    start = time.time()
    state = run_ingest(state, model)
    state.setdefault("metadata", {})["ingest_time"] = round(time.time() - start, 2)
    return state


def detect_node(state: AgentState) -> AgentState:
    model = state.get("metadata", {}).get("model_name", "deepseek-chat")
    start = time.time()
    state = run_detect(state, model)
    state.setdefault("metadata", {})["detect_time"] = round(time.time() - start, 2)
    return state


def classify_node(state: AgentState) -> AgentState:
    model = state.get("metadata", {}).get("model_name", "deepseek-chat")
    start = time.time()
    state = run_classify(state, model)
    state.setdefault("metadata", {})["classify_time"] = round(time.time() - start, 2)
    return state


def report_node(state: AgentState) -> AgentState:
    model = state.get("metadata", {}).get("model_name", "deepseek-chat")
    start = time.time()
    state = run_report(state, model)
    state.setdefault("metadata", {})["report_time"] = round(time.time() - start, 2)
    return state


def should_classify(state: AgentState) -> str:
    """Route to classify only if threats were found."""
    if state.get("threats") and len(state["threats"]) > 0:
        return "classify"
    return "skip_to_report"


def should_report(state: AgentState) -> str:
    """Route to report only if there are classifications with sufficient risk."""
    classifications = state.get("classifications", [])
    if not classifications:
        return "end"

    # Check if any finding has risk_score >= 3 (medium or above)
    for inc in classifications:
        if inc.get("max_risk_score", 0) >= 3:
            return "report"
        for f in inc.get("findings", []):
            if f.get("risk_score", 0) >= 3:
                return "report"

    return "report"  # Still generate report even for low-risk findings


def build_graph() -> StateGraph:
    """Build and compile the cyber defense agent pipeline."""
    graph = StateGraph(AgentState)

    # Add nodes
    graph.add_node("ingest", ingest_node)
    graph.add_node("detect", detect_node)
    graph.add_node("classify", classify_node)
    graph.add_node("report", report_node)

    # Set entry point
    graph.set_entry_point("ingest")

    # Ingest always goes to detect
    graph.add_edge("ingest", "detect")

    # Detect conditionally routes to classify or skips
    graph.add_conditional_edges(
        "detect",
        should_classify,
        {
            "classify": "classify",
            "skip_to_report": "report",
        }
    )

    # Classify conditionally routes to report or end
    graph.add_conditional_edges(
        "classify",
        should_report,
        {
            "report": "report",
            "end": END,
        }
    )

    # Report always ends
    graph.add_edge("report", END)

    return graph.compile()


def run_pipeline(logs: str, model_name: str = "deepseek-chat") -> AgentState:
    """Run the full pipeline on raw log data."""
    pipeline = build_graph()
    initial_state: AgentState = {
        "logs": logs,
        "normalized_events": [],
        "threats": [],
        "classifications": [],
        "report": "",
        "agent_reasoning": {},
        "metadata": {"model_name": model_name, "start_time": time.time()},
    }

    result = pipeline.invoke(initial_state)
    result["metadata"]["total_time"] = round(time.time() - result["metadata"]["start_time"], 2)
    return result
