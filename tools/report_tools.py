"""Tools for generating incident reports and action recommendations."""

import json
from datetime import datetime
from langchain_core.tools import tool


@tool
def report_generator(incidents_json: str) -> str:
    """Generate a structured Markdown incident report from correlated incidents.

    Args:
        incidents_json: JSON string of correlated incidents.

    Returns:
        Markdown formatted incident report string.
    """
    data = json.loads(incidents_json)
    incidents = data if isinstance(data, list) else data.get("incidents", [])

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for inc in incidents:
        for f in inc.get("findings", []):
            sev = f.get("severity", "medium")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

    total_findings = sum(severity_counts.values())

    lines = [
        "# Security Incident Report",
        f"\n**Generated:** {now}",
        f"\n**Total Incidents:** {len(incidents)}",
        f"**Total Findings:** {total_findings}",
        "",
        "## Severity Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| Critical | {severity_counts['critical']} |",
        f"| High | {severity_counts['high']} |",
        f"| Medium | {severity_counts['medium']} |",
        f"| Low | {severity_counts['low']} |",
        "",
        "---",
        "",
    ]

    # Detail each incident
    for i, inc in enumerate(incidents, 1):
        coordinated = " [COORDINATED ATTACK]" if inc.get("is_coordinated_attack") else ""
        lines.append(f"## Incident {i}: {inc.get('description', 'Unknown')}{coordinated}")
        lines.append("")
        lines.append(f"- **Source IP:** {inc.get('source_ip', 'N/A')}")
        lines.append(f"- **Max Risk Score:** {inc.get('max_risk_score', 0)}/10")
        lines.append(f"- **Threat Types:** {', '.join(inc.get('threat_types', []))}")
        lines.append(f"- **Finding Count:** {inc.get('finding_count', 0)}")
        lines.append("")

        for j, finding in enumerate(inc.get("findings", []), 1):
            lines.append(f"### Finding {i}.{j}: {finding.get('type', 'unknown')}")
            lines.append(f"- **Severity:** {finding.get('severity', 'unknown').upper()}")
            lines.append(f"- **Risk Score:** {finding.get('risk_score', 0)}/10")
            lines.append(f"- **Description:** {finding.get('description', '')}")
            if finding.get("mitre_technique"):
                lines.append(f"- **MITRE ATT&CK:** {finding['mitre_technique']}")
            if finding.get("cve_references"):
                lines.append(f"- **CVE References:** {', '.join(finding['cve_references'])}")
            if finding.get("recommended_response"):
                lines.append(f"- **Recommended Response:** {finding['recommended_response']}")
            lines.append("")

        lines.append("---")
        lines.append("")

    return "\n".join(lines)


@tool
def action_recommender(incidents_json: str) -> str:
    """Generate prioritized action recommendations based on incidents.

    Args:
        incidents_json: JSON string of correlated incidents.

    Returns:
        Markdown formatted action plan.
    """
    data = json.loads(incidents_json)
    incidents = data if isinstance(data, list) else data.get("incidents", [])

    immediate = []
    urgent = []
    general = []

    ips_to_block = set()

    for inc in incidents:
        score = inc.get("max_risk_score", 0)
        ip = inc.get("source_ip", "")

        for finding in inc.get("findings", []):
            resp = finding.get("recommended_response", "")
            ftype = finding.get("type", "")
            severity = finding.get("severity", "medium")

            if severity == "critical":
                immediate.append(f"**{ftype.upper()}**: {resp} (Source: {ip})")
                if ip and ip != "N/A":
                    ips_to_block.add(ip)
            elif severity == "high":
                urgent.append(f"**{ftype}**: {resp} (Source: {ip})")
                if ip and ip != "N/A":
                    ips_to_block.add(ip)
            else:
                general.append(f"**{ftype}**: {resp}")

    lines = [
        "## Recommended Actions",
        "",
    ]

    if ips_to_block:
        lines.append("### IPs to Block Immediately")
        lines.append("")
        for ip in sorted(ips_to_block):
            lines.append(f"- `{ip}`")
        lines.append("")

    if immediate:
        lines.append("### Immediate Actions (Critical)")
        lines.append("")
        for action in immediate:
            lines.append(f"1. {action}")
        lines.append("")

    if urgent:
        lines.append("### Urgent Actions (High)")
        lines.append("")
        for action in urgent:
            lines.append(f"1. {action}")
        lines.append("")

    if general:
        lines.append("### General Recommendations")
        lines.append("")
        for action in general:
            lines.append(f"- {action}")
        lines.append("")

    if not (immediate or urgent or general):
        lines.append("No significant threats detected. Continue routine monitoring.")
        lines.append("")

    return "\n".join(lines)
