"""Report Agent — generates markdown incident reports with action plans."""

import json
import os
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from tools.report_tools import report_generator, action_recommender


REPORT_SYSTEM_PROMPT = """You are a Security Report Agent. Your job is to:
1. Generate a structured incident report using the report_generator tool
2. Create an action plan using the action_recommender tool

Combine both outputs into a single comprehensive report. Add an executive summary at the top
highlighting the most critical findings and recommended immediate actions."""


def create_report_agent(model_name: str = "deepseek-chat"):
    llm = ChatOpenAI(
        model=model_name,
        temperature=0,
        api_key=os.environ.get("DEEPSEEK_API_KEY"),
        base_url="https://api.deepseek.com",
    )
    return create_react_agent(
        llm,
        tools=[report_generator, action_recommender],
        prompt=REPORT_SYSTEM_PROMPT,
    )


def run_report(state: dict, model_name: str = "gpt-4o-mini") -> dict:
    """Generate the final report: report_generator + action_recommender (deterministic), then LLM for executive summary."""
    incidents_json = json.dumps({"incidents": state["classifications"]})

    # Step 1: Generate structured report
    report_md = report_generator.invoke(incidents_json)

    # Step 2: Generate action recommendations
    actions_md = action_recommender.invoke(incidents_json)

    # Step 3: Use LLM to write executive summary
    llm = ChatOpenAI(
        model=model_name,
        temperature=0,
        api_key=os.environ.get("DEEPSEEK_API_KEY"),
        base_url="https://api.deepseek.com",
    )

    summary_prompt = (
        f"Write a brief executive summary (3-5 sentences) for this security incident report. "
        f"Focus on the most critical findings and immediate actions needed.\n\n"
        f"Report:\n{report_md}\n\nActions:\n{actions_md}"
    )
    summary_result = llm.invoke(summary_prompt)
    exec_summary = summary_result.content if hasattr(summary_result, 'content') else str(summary_result)

    full_report = f"# Executive Summary\n\n{exec_summary}\n\n{report_md}\n\n{actions_md}"

    state["report"] = full_report
    state["agent_reasoning"] = state.get("agent_reasoning", {})
    state["agent_reasoning"]["report"] = f"Generated structured report, action plan, and executive summary via {model_name}."
    return state
