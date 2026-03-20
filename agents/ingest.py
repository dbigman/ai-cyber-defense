"""Ingest Agent — parses, validates, and normalizes security log data."""

import json
import os
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from tools.ingestion_tools import parse_log, validate_entry, normalize_data


INGEST_SYSTEM_PROMPT = """You are a Security Log Ingestion Agent. Your job is to:
1. Parse raw security log data using the parse_log tool
2. Validate all entries using the validate_entry tool
3. Normalize the validated data using the normalize_data tool

Always run all three tools in sequence. Pass the output of each tool as input to the next.
Be thorough — report any parsing errors or validation issues found."""


def create_ingest_agent(model_name: str = "deepseek-chat"):
    llm = ChatOpenAI(
        model=model_name,
        temperature=0,
        api_key=os.environ.get("DEEPSEEK_API_KEY"),
        base_url="https://api.deepseek.com",
    )
    return create_react_agent(
        llm,
        tools=[parse_log, validate_entry, normalize_data],
        prompt=INGEST_SYSTEM_PROMPT,
    )


def run_ingest(state: dict, model_name: str = "gpt-4o-mini") -> dict:
    """Run the ingest pipeline: parse → validate → normalize (deterministic tool chain)."""
    raw_logs = state["logs"]

    # Step 1: Parse
    parsed_result = parse_log.invoke(raw_logs)
    parsed_data = json.loads(parsed_result)

    # Step 2: Validate
    validated_result = validate_entry.invoke(json.dumps(parsed_data))
    validated_data = json.loads(validated_result)

    # Step 3: Normalize
    normalized_result = normalize_data.invoke(json.dumps(validated_data))
    normalized_data = json.loads(normalized_result)

    normalized_events = normalized_data.get("normalized_events", [])

    reasoning = (
        f"Parsed {parsed_data.get('total', 0)} events ({parsed_data.get('parse_errors', 0)} errors). "
        f"Validated: {validated_data.get('valid_count', 0)} valid, {validated_data.get('invalid_count', 0)} invalid. "
        f"Normalized {len(normalized_events)} events."
    )

    state["normalized_events"] = normalized_events
    state["agent_reasoning"] = state.get("agent_reasoning", {})
    state["agent_reasoning"]["ingest"] = reasoning
    return state
