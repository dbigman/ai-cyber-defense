"""Tools for parsing, validating, and normalizing security log data."""

import json
from datetime import datetime
from langchain_core.tools import tool


REQUIRED_FIELDS = {"timestamp", "source_ip", "event_type"}
VALID_EVENT_TYPES = {
    "login_attempt", "login_success", "login_failure", "logout",
    "file_access", "file_modify", "file_delete",
    "privilege_escalation", "sudo_command",
    "network_connection", "port_scan", "dns_query",
    "firewall_block", "firewall_allow",
    "malware_detected", "intrusion_attempt",
    "config_change", "service_start", "service_stop",
    "authentication_failure", "account_lockout",
}


@tool
def parse_log(raw_data: str) -> str:
    """Parse raw security log data from JSON string into structured events.

    Args:
        raw_data: JSON string containing security log entries (array of objects).

    Returns:
        JSON string of parsed events with parse status.
    """
    try:
        data = json.loads(raw_data)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid JSON: {e}", "parsed_events": [], "parse_errors": 1})

    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return json.dumps({"error": "Expected JSON array of log entries", "parsed_events": [], "parse_errors": 1})

    parsed = []
    errors = 0
    for i, entry in enumerate(data):
        if not isinstance(entry, dict):
            errors += 1
            continue
        entry["_index"] = i
        entry["_parse_status"] = "ok"
        parsed.append(entry)

    return json.dumps({
        "parsed_events": parsed,
        "total": len(parsed),
        "parse_errors": errors,
    })


@tool
def validate_entry(events_json: str) -> str:
    """Validate parsed log entries for required fields and data quality.

    Args:
        events_json: JSON string of parsed events list.

    Returns:
        JSON string with validation results per event.
    """
    events = json.loads(events_json)
    if isinstance(events, dict) and "parsed_events" in events:
        events = events["parsed_events"]

    results = []
    valid_count = 0
    for event in events:
        issues = []
        for field in REQUIRED_FIELDS:
            if field not in event or not event[field]:
                issues.append(f"missing required field: {field}")

        if "event_type" in event:
            et = event["event_type"].lower().strip()
            if et not in VALID_EVENT_TYPES:
                issues.append(f"unknown event_type: {et}")

        if "source_ip" in event:
            ip = event["source_ip"]
            parts = ip.split(".")
            if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                if ":" not in ip:  # allow IPv6
                    issues.append(f"malformed IP: {ip}")

        if "timestamp" in event:
            ts = event["timestamp"]
            parsed_ok = False
            for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%b %d %H:%M:%S"):
                try:
                    datetime.strptime(ts, fmt)
                    parsed_ok = True
                    break
                except ValueError:
                    continue
            if not parsed_ok:
                issues.append(f"unparseable timestamp: {ts}")

        event["_validation_issues"] = issues
        event["_valid"] = len(issues) == 0
        if event["_valid"]:
            valid_count += 1
        results.append(event)

    return json.dumps({
        "validated_events": results,
        "valid_count": valid_count,
        "invalid_count": len(results) - valid_count,
    })


@tool
def normalize_data(events_json: str) -> str:
    """Normalize validated log events: standardize timestamps, lowercase event types, enrich with derived fields.

    Args:
        events_json: JSON string of validated events.

    Returns:
        JSON string of normalized events.
    """
    events = json.loads(events_json)
    if isinstance(events, dict) and "validated_events" in events:
        events = events["validated_events"]

    normalized = []
    for event in events:
        norm = dict(event)

        # Normalize event_type
        if "event_type" in norm:
            norm["event_type"] = norm["event_type"].lower().strip()

        # Normalize status
        if "status" in norm:
            norm["status"] = norm["status"].lower().strip()

        # Normalize user
        if "user" in norm:
            norm["user"] = norm["user"].strip()

        # Parse timestamp to ISO format
        if "timestamp" in norm:
            ts = norm["timestamp"]
            for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S"):
                try:
                    dt = datetime.strptime(ts, fmt)
                    norm["timestamp_iso"] = dt.isoformat()
                    norm["hour"] = dt.hour
                    break
                except ValueError:
                    continue

        # Derive direction
        if "destination_ip" in norm:
            src = norm.get("source_ip", "")
            if src.startswith("10.") or src.startswith("192.168.") or src.startswith("172."):
                norm["direction"] = "outbound" if not (
                    norm["destination_ip"].startswith("10.") or
                    norm["destination_ip"].startswith("192.168.") or
                    norm["destination_ip"].startswith("172.")
                ) else "internal"
            else:
                norm["direction"] = "inbound"

        normalized.append(norm)

    return json.dumps({"normalized_events": normalized, "count": len(normalized)})
