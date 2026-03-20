"""Gradio dashboard for the AI Cyber Defense Multi-Agent System."""

import json
import os
import tempfile

import gradio as gr
import pandas as pd
from dotenv import load_dotenv

load_dotenv()


def analyze_logs(file, model_name, show_reasoning):
    """Run the pipeline on uploaded log file and return results."""
    if file is None:
        return "No file uploaded.", "", None, "", "", None

    # Read file content
    if hasattr(file, "name"):
        with open(file.name, "r") as f:
            logs = f.read()
    else:
        logs = file

    try:
        data = json.loads(logs)
        event_count = len(data) if isinstance(data, list) else 1
    except json.JSONDecodeError:
        return "Error: Invalid JSON file.", "", None, "", "", None

    if not os.environ.get("DEEPSEEK_API_KEY"):
        return "Error: DEEPSEEK_API_KEY not set. Add it to your .env file.", "", None, "", "", None

    from agents.graph import run_pipeline

    try:
        result = run_pipeline(logs, model_name=model_name)
    except Exception as e:
        return f"Pipeline error: {e}", "", None, "", "", None

    # Build severity chart data
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    classifications = result.get("classifications", [])
    for inc in classifications:
        for f_item in inc.get("findings", []):
            sev = f_item.get("severity", "medium").capitalize()
            if sev in severity_counts:
                severity_counts[sev] += 1

    # If no structured incidents, count from threats directly
    if not any(severity_counts.values()):
        for t in result.get("threats", []):
            hint = t.get("severity_hint", "medium").capitalize()
            if hint in severity_counts:
                severity_counts[hint] += 1

    chart_data = pd.DataFrame({
        "Severity": list(severity_counts.keys()),
        "Count": list(severity_counts.values()),
    })

    # Build findings table
    findings_rows = []
    for inc in classifications:
        for f_item in inc.get("findings", []):
            findings_rows.append([
                f_item.get("severity", "").upper(),
                f_item.get("type", ""),
                f_item.get("source_ip", inc.get("source_ip", "N/A")),
                f_item.get("description", ""),
                f_item.get("mitre_technique", ""),
                str(f_item.get("risk_score", "")),
            ])

    if not findings_rows:
        for t in result.get("threats", []):
            findings_rows.append([
                t.get("severity_hint", "").upper(),
                t.get("type", ""),
                t.get("source_ip", "N/A"),
                t.get("description", ""),
                "",
                "",
            ])

    # Build status summary
    meta = result.get("metadata", {})
    status = f"""**Analysis Complete**
- Events processed: {len(result.get('normalized_events', []))}
- Threats detected: {len(result.get('threats', []))}
- Incidents classified: {len(classifications)}
- Total time: {meta.get('total_time', '?')}s
- Model: {model_name}"""

    # Report
    report = result.get("report", "No report generated.")

    # Agent reasoning
    reasoning_text = ""
    if show_reasoning:
        for agent, text in result.get("agent_reasoning", {}).items():
            if text:
                reasoning_text += f"### {agent.upper()} Agent\n{text}\n\n"

    # Save report to temp file for download
    report_path = None
    if report and report != "No report generated.":
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False, prefix="incident_report_", encoding="utf-8")
        tmp.write(report)
        tmp.close()
        report_path = tmp.name

    return status, report, chart_data, findings_rows, reasoning_text, report_path


def build_dashboard():
    """Build and return the Gradio interface."""
    with gr.Blocks(title="AI Cyber Defense Dashboard") as demo:
        gr.Markdown("# AI Cyber Defense Multi-Agent System")
        gr.Markdown("Upload security logs to analyze threats using a LangGraph multi-agent pipeline.")

        with gr.Row():
            with gr.Column(scale=1):
                file_input = gr.File(label="Upload Security Logs (JSON)", file_types=[".json"])
                model_select = gr.Dropdown(
                    choices=["deepseek-chat", "deepseek-reasoner"],
                    value="deepseek-chat",
                    label="Model",
                )
                show_reasoning = gr.Checkbox(label="Show Agent Reasoning", value=False)
                analyze_btn = gr.Button("Analyze Logs", variant="primary", size="lg")

            with gr.Column(scale=1):
                status_output = gr.Markdown(label="Status")

        with gr.Tabs():
            with gr.TabItem("Severity Chart"):
                severity_chart = gr.BarPlot(
                    x="Severity",
                    y="Count",
                    title="Findings by Severity",
                    color="Severity",
                    x_title="Severity Level",
                    y_title="Count",
                )

            with gr.TabItem("Findings Table"):
                findings_table = gr.Dataframe(
                    headers=["Severity", "Type", "Source IP", "Description", "MITRE ATT&CK", "Risk Score"],
                    label="Detailed Findings",
                )

            with gr.TabItem("Full Report"):
                report_output = gr.Markdown(label="Incident Report")
                report_download = gr.File(label="Download Report")

            with gr.TabItem("Agent Reasoning"):
                reasoning_output = gr.Markdown(label="Agent Reasoning Traces")

        analyze_btn.click(
            fn=analyze_logs,
            inputs=[file_input, model_select, show_reasoning],
            outputs=[status_output, report_output, severity_chart, findings_table, reasoning_output, report_download],
        )

    return demo


if __name__ == "__main__":
    demo = build_dashboard()
    demo.launch(server_name="0.0.0.0", server_port=7860, theme=gr.themes.Soft())
