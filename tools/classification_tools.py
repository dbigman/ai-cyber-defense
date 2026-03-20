"""Tools for classifying threats: risk scoring, context enrichment, event correlation."""

import json
from collections import defaultdict
from langchain_core.tools import tool


SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 1,
}

# Simulated threat context DB
THREAT_CONTEXT = {
    "brute_force": {
        "mitre_technique": "T1110 - Brute Force",
        "cve_references": [],
        "typical_response": "Block source IP, enforce account lockout, review affected accounts",
    },
    "credential_stuffing": {
        "mitre_technique": "T1110.004 - Credential Stuffing",
        "cve_references": [],
        "typical_response": "Block source IP, force password resets for targeted accounts, enable MFA",
    },
    "port_scan": {
        "mitre_technique": "T1046 - Network Service Scanning",
        "cve_references": [],
        "typical_response": "Block source IP at firewall, review exposed services",
    },
    "privilege_escalation": {
        "mitre_technique": "T1078 - Valid Accounts / T1548 - Abuse Elevation Control",
        "cve_references": ["CVE-2021-4034"],
        "typical_response": "Immediately investigate user account, revoke elevated privileges, audit sudo config",
    },
    "attack_tool_detected": {
        "mitre_technique": "T1595 - Active Scanning",
        "cve_references": [],
        "typical_response": "Block source IP, conduct full network scan for compromise indicators",
    },
    "known_malicious_ip": {
        "mitre_technique": "T1071 - Application Layer Protocol",
        "cve_references": [],
        "typical_response": "Block IP at perimeter firewall, investigate all connections from this IP",
    },
    "off_hours_login": {
        "mitre_technique": "T1078 - Valid Accounts",
        "cve_references": [],
        "typical_response": "Verify with user, check for lateral movement",
    },
    "geo_anomaly": {
        "mitre_technique": "T1078 - Valid Accounts",
        "cve_references": [],
        "typical_response": "Force re-authentication, verify user location, check for compromised credentials",
    },
    "impossible_travel": {
        "mitre_technique": "T1078 - Valid Accounts",
        "cve_references": [],
        "typical_response": "Lock account, force password reset, investigate for credential theft",
    },
    "volume_spike": {
        "mitre_technique": "T1498 - Network Denial of Service",
        "cve_references": [],
        "typical_response": "Rate limit source, investigate for DDoS or automated scanning",
    },
    "rare_critical_event": {
        "mitre_technique": "varies",
        "cve_references": [],
        "typical_response": "Immediate investigation required",
    },
    "sensitive_file_access": {
        "mitre_technique": "T1005 - Data from Local System / T1039 - Data from Network Shared Drive",
        "cve_references": [],
        "typical_response": "Verify authorization, check for data exfiltration, review DLP logs, lock account if from external IP",
    },
    "post_exploitation_chain": {
        "mitre_technique": "T1548 - Abuse Elevation Control → T1003 - OS Credential Dumping → T1098 - Account Manipulation",
        "cve_references": ["CVE-2021-4034"],
        "typical_response": "CRITICAL: Isolate affected host immediately, revoke all credentials, forensic imaging, check for persistence mechanisms",
    },
    "intrusion_attempt": {
        "mitre_technique": "T1190 - Exploit Public-Facing Application",
        "cve_references": [],
        "typical_response": "Block source IP, review WAF rules, check application logs for successful exploitation, patch vulnerable services",
    },
    "ransomware_activity": {
        "mitre_technique": "T1486 - Data Encrypted for Impact",
        "cve_references": [],
        "typical_response": "CRITICAL: Isolate affected systems immediately, do NOT pay ransom, restore from backups, check for lateral spread",
    },
    "malware_detected": {
        "mitre_technique": "T1059 - Command and Scripting Interpreter / T1071 - Application Layer Protocol",
        "cve_references": [],
        "typical_response": "Isolate host, capture memory dump for forensics, check for persistence, review EDR/AV logs",
    },
    "mass_file_modification": {
        "mitre_technique": "T1486 - Data Encrypted for Impact / T1565 - Data Manipulation",
        "cve_references": [],
        "typical_response": "CRITICAL: Possible ransomware - isolate host, stop encryption in progress, check backup integrity",
    },
    "data_exfiltration": {
        "mitre_technique": "T1041 - Exfiltration Over C2 Channel / T1567 - Exfiltration Over Web Service",
        "cve_references": [],
        "typical_response": "Block destination IP, revoke compromised credentials, assess data scope, notify legal/PR if PII involved",
    },
}


@tool
def risk_scorer(threats_json: str) -> str:
    """Score each threat/anomaly for risk severity based on type, evidence strength, and context.

    Assigns: critical (9-10), high (6-8), medium (3-5), low (1-2).

    Args:
        threats_json: JSON string containing threats and anomalies.

    Returns:
        JSON string with risk-scored classifications.
    """
    data = json.loads(threats_json)
    threats = data if isinstance(data, list) else data.get("threats", []) + data.get("anomalies", []) + data.get("threat_intel_hits", [])

    scored = []
    for t in threats:
        base = SEVERITY_WEIGHTS.get(t.get("severity_hint", "medium"), 4)

        # Boost score for multiple pieces of evidence
        count = t.get("attempt_count", t.get("port_count", t.get("user_count", 1)))
        if count >= 10:
            base = min(base + 2, 10)
        elif count >= 5:
            base = min(base + 1, 10)

        # Boost for privilege escalation or known malicious IP
        if t.get("type") in ("privilege_escalation", "known_malicious_ip", "attack_tool_detected"):
            base = min(base + 1, 10)

        # Map score to severity
        if base >= 9:
            severity = "critical"
        elif base >= 6:
            severity = "high"
        elif base >= 3:
            severity = "medium"
        else:
            severity = "low"

        scored.append({
            **t,
            "risk_score": base,
            "severity": severity,
        })

    scored.sort(key=lambda x: x["risk_score"], reverse=True)
    return json.dumps({"classifications": scored, "total": len(scored)})


@tool
def context_enricher(classifications_json: str) -> str:
    """Enrich classified threats with MITRE ATT&CK references, CVEs, and response guidance.

    Args:
        classifications_json: JSON string of scored classifications.

    Returns:
        JSON string of enriched classifications.
    """
    data = json.loads(classifications_json)
    items = data if isinstance(data, list) else data.get("classifications", [])

    enriched = []
    for item in items:
        threat_type = item.get("type", "")
        ctx = THREAT_CONTEXT.get(threat_type, {
            "mitre_technique": "unknown",
            "cve_references": [],
            "typical_response": "Investigate and assess impact",
        })
        enriched.append({
            **item,
            "mitre_technique": ctx["mitre_technique"],
            "cve_references": ctx["cve_references"],
            "recommended_response": ctx["typical_response"],
        })

    return json.dumps({"enriched_classifications": enriched, "total": len(enriched)})


@tool
def event_correlator(classifications_json: str) -> str:
    """Correlate related threats into incident groups (e.g., scan + brute force + escalation from same IP = coordinated attack).

    Args:
        classifications_json: JSON string of enriched classifications.

    Returns:
        JSON string with correlated incident groups.
    """
    data = json.loads(classifications_json)
    items = data if isinstance(data, list) else data.get("enriched_classifications", data.get("classifications", []))

    # Group by source IP
    ip_groups = defaultdict(list)
    ungrouped = []
    for item in items:
        ip = item.get("source_ip", "")
        if ip:
            ip_groups[ip].append(item)
        else:
            ungrouped.append(item)

    incidents = []
    for ip, group in ip_groups.items():
        types = set(g["type"] for g in group)
        max_score = max(g.get("risk_score", 0) for g in group)

        # Detect coordinated attack patterns
        is_coordinated = len(types) >= 2 and any(
            t in types for t in ("port_scan", "brute_force", "privilege_escalation", "credential_stuffing")
        )

        if is_coordinated:
            max_score = min(max_score + 1, 10)

        incidents.append({
            "source_ip": ip,
            "threat_types": sorted(types),
            "findings": group,
            "finding_count": len(group),
            "max_risk_score": max_score,
            "is_coordinated_attack": is_coordinated,
            "description": f"{'Coordinated attack' if is_coordinated else 'Activity'} from {ip}: {', '.join(sorted(types))}",
        })

    # Add ungrouped items as individual incidents
    for item in ungrouped:
        incidents.append({
            "source_ip": "N/A",
            "threat_types": [item.get("type", "unknown")],
            "findings": [item],
            "finding_count": 1,
            "max_risk_score": item.get("risk_score", 0),
            "is_coordinated_attack": False,
            "description": item.get("description", ""),
        })

    incidents.sort(key=lambda x: x["max_risk_score"], reverse=True)
    return json.dumps({"incidents": incidents, "incident_count": len(incidents)})
