"""Report Agent — generates markdown incident reports with action plans."""

import json
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from tools.report_tools import report_generator, action_recommender


REPORT_SYSTEM_PROMPT = """You are a Security Report Agent. Your job is to:
1. Generate a structured incident report using the report_generator tool
2. Create an action plan using the action_recommender tool

Combine both outputs into a single comprehensive report. Add an executive summary at the top
highlighting the most critical findings and recommended immediate actions."""


def create_report_agent(model_name: str = "gpt-4o-mini"):
    llm = ChatOpenAI(model=model_name, temperature=0)
    return create_react_agent(
        llm,
        tools=[report_generator, action_recommender],
        prompt=REPORT_SYSTEM_PROMPT,
    )


def run_report(state: dict, model_name: str = "gpt-4o-mini") -> dict:
    """Generate the final report and update state."""
    agent = create_report_agent(model_name)
    incidents_json = json.dumps({"incidents": state["classifications"]})

    result = agent.invoke({
        "messages": [
            {"role": "user", "content": f"Generate a complete incident report and action plan for these incidents:\n\n{incidents_json}"}
        ]
    })

    # Collect report parts from tool outputs and final AI message
    report_parts = []
    reasoning = ""
    for msg in result["messages"]:
        if hasattr(msg, "content") and isinstance(msg.content, str):
            content = msg.content
            # Tool outputs are the raw report/action sections
            if hasattr(msg, "type") and msg.type == "tool":
                if content.startswith("#") or content.startswith("##"):
                    report_parts.append(content)
            elif hasattr(msg, "type") and msg.type == "ai" and not hasattr(msg, "tool_calls"):
                reasoning += content + "\n"

    # If tool outputs captured, combine them; otherwise use the last AI message
    if report_parts:
        state["report"] = "\n\n".join(report_parts)
    elif reasoning.strip():
        state["report"] = reasoning.strip()
    else:
        state["report"] = "No report generated."

    state["agent_reasoning"] = state.get("agent_reasoning", {})
    state["agent_reasoning"]["report"] = reasoning.strip()
    return state
