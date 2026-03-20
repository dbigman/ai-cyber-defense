"""AgentState definition for the cyber defense pipeline."""

from typing import TypedDict, Any


class AgentState(TypedDict):
    """Shared state passed through the LangGraph pipeline."""

    # Raw log data (string or list of dicts)
    logs: str
    # Parsed and normalized events
    normalized_events: list[dict[str, Any]]
    # Detected threats from the detect agent
    threats: list[dict[str, Any]]
    # Classified threats with severity and context
    classifications: list[dict[str, Any]]
    # Final markdown report
    report: str
    # Per-agent reasoning traces
    agent_reasoning: dict[str, str]
    # Pipeline metadata (model, timings, etc.)
    metadata: dict[str, Any]
