"""Ingest Agent — parses, validates, and normalizes security log data."""

import json
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from tools.ingestion_tools import parse_log, validate_entry, normalize_data


INGEST_SYSTEM_PROMPT = """You are a Security Log Ingestion Agent. Your job is to:
1. Parse raw security log data using the parse_log tool
2. Validate all entries using the validate_entry tool
3. Normalize the validated data using the normalize_data tool

Always run all three tools in sequence. Pass the output of each tool as input to the next.
Be thorough — report any parsing errors or validation issues found."""


def create_ingest_agent(model_name: str = "gpt-4o-mini"):
    llm = ChatOpenAI(model=model_name, temperature=0)
    return create_react_agent(
        llm,
        tools=[parse_log, validate_entry, normalize_data],
        prompt=INGEST_SYSTEM_PROMPT,
    )


def run_ingest(state: dict, model_name: str = "gpt-4o-mini") -> dict:
    """Run the ingest agent on raw logs and update state."""
    agent = create_ingest_agent(model_name)

    result = agent.invoke({
        "messages": [
            {"role": "user", "content": f"Parse, validate, and normalize these security logs:\n\n{state['logs']}"}
        ]
    })

    # Extract normalized events from the agent's tool calls
    normalized_events = []
    reasoning = ""
    for msg in result["messages"]:
        if hasattr(msg, "content") and isinstance(msg.content, str):
            # Check if this is a tool response with normalized data
            try:
                data = json.loads(msg.content)
                if "normalized_events" in data:
                    normalized_events = data["normalized_events"]
            except (json.JSONDecodeError, TypeError):
                pass
            # Collect agent reasoning from non-tool messages
            if hasattr(msg, "type") and msg.type == "ai":
                reasoning += msg.content + "\n"

    state["normalized_events"] = normalized_events
    state["agent_reasoning"] = state.get("agent_reasoning", {})
    state["agent_reasoning"]["ingest"] = reasoning.strip()
    return state
