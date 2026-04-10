#!/usr/bin/env python3
"""
Windows Event Log Ingester for AI Cyber Defense Pipeline.

Pulls security events from the local Windows Event Log via PowerShell
Get-WinEvent, parses XML event data, and formats for the LangGraph pipeline.

Usage:
    python integrations/windows_event_ingester.py [--hours N] [--output PATH]

Requires: PowerShell 5.1+, admin rights for Security log access.
"""

import argparse
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from pathlib import Path

# --- Event ID mapping ---
EVENT_MAP = {
    4625: {"event_type": "login_attempt",     "status": "failure", "label": "Failed Logon"},
    4624: {"event_type": "login_attempt",     "status": "success", "label": "Successful Logon"},
    4688: {"event_type": "process_creation",  "status": "success", "label": "New Process Created"},
    4672: {"event_type": "privilege_escalation", "status": "success", "label": "Special Privileges Assigned"},
    4720: {"event_type": "user_created",      "status": "success", "label": "User Account Created"},
    4732: {"event_type": "group_modified",    "status": "success", "label": "Member Added to Local Group"},
    4740: {"event_type": "account_locked",    "status": "failure", "label": "Account Locked Out"},
    1102: {"event_type": "audit_log_cleared", "status": "success", "label": "Audit Log Cleared"},
}

# Logon type mapping
LOGON_TYPE_MAP = {
    "2":  "Interactive",
    "3":  "Network",
    "4":  "Batch",
    "5":  "Service",
    "7":  "Unlock",
    "8":  "NetworkCleartext",
    "9":  "NewCredentials",
    "10": "RemoteInteractive",
    "11": "CachedInteractive",
}

# Namespace for Windows event XML
NS = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}


def build_powershell_query(log_name: str, event_ids: list[int], hours: int) -> str:
    """Build the PowerShell Get-WinEvent query string."""
    id_filter = ",".join(str(i) for i in event_ids)
    start_time = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    ps = f"""
$ErrorActionPreference = 'Stop'
$start = [DateTime]::Parse("{start_time}")
$ids = @({id_filter})
$filter = @{{
    LogName = '{log_name}'
    Id = $ids
    StartTime = $start
}}
try {{
    $events = Get-WinEvent -FilterHashtable $filter -MaxEvents 1000 -ErrorAction Stop
}} catch [System.Exception] {{
    if ($_.Exception.Message -match 'No events were found') {{
        Write-Output "NO_EVENTS"
        exit 0
    }}
    Write-Error $_.Exception.Message
    exit 1
}}
foreach ($evt in $events) {{
    $xml = [xml]$evt.ToXml()
    Write-Output "===EVENT==="
    Write-Output $xml.OuterXml
}}
"""
    return ps


def extract_field(event_data: ET.Element, name: str) -> str:
    """Extract a named data field from the EventData section."""
    for data in event_data.findall("ns:Data", NS):
        if data.get("Name") == name:
            return (data.text or "").strip()
    return ""


def parse_event(xml_str: str, local_ip: str) -> dict | None:
    """Parse a single Windows event XML into pipeline format."""
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    system = root.find("ns:System", NS)
    event_data = root.find("ns:EventData", NS)

    if system is None:
        return None

    event_id_el = system.find("ns:EventID", NS)
    event_id = int(event_id_el.text) if event_id_el is not None else None
    if event_id not in EVENT_MAP:
        return None

    time_el = system.find("ns:TimeCreated", NS)
    timestamp = time_el.get("SystemTime", "") if time_el is not None else ""

    mapping = EVENT_MAP[event_id]

    # Extract common fields
    target_user = extract_field(event_data, "TargetUserName") or extract_field(event_data, "SubjectUserName")
    source_ip = extract_field(event_data, "IpAddress")
    source_port = extract_field(event_data, "IpPort")
    logon_type = extract_field(event_data, "LogonType")

    # For 4688 (process creation)
    new_process = extract_field(event_data, "NewProcessName")
    creator_process = extract_field(event_data, "CreatorProcessName")
    command_line = extract_field(event_data, "CommandLine")

    # For 4732 (group modification)
    group_name = extract_field(event_data, "GroupName")
    member_sid = extract_field(event_data, "MemberSid")

    # For 1102 (audit cleared)
    subject = extract_field(event_data, "SubjectUserName")

    # Build message
    messages = {
        4625: f"Failed logon attempt for '{target_user}' from {source_ip or 'N/A'} (LogonType: {logon_type})",
        4624: f"Successful logon for '{target_user}' from {source_ip or 'N/A'} (LogonType: {logon_type})",
        4688: f"Process created: {new_process} by '{target_user}'" + (f" cmdline: {command_line}" if command_line else ""),
        4672: f"Special privileges assigned to '{target_user}'",
        4720: f"User account '{target_user}' was created",
        4732: f"Member {member_sid} added to local group '{group_name}'",
        4740: f"Account '{target_user}' was locked out from {source_ip or 'N/A'}",
        1102: f"Audit log was cleared by '{subject or 'SYSTEM'}'",
    }

    # For 4624, skip local/empty source IPs to reduce noise
    if event_id == 4624:
        if not source_ip or source_ip in ("-", "::1", "127.0.0.1", local_ip):
            return None

    # Determine protocol/port
    protocol = "Windows Auth"
    port = None
    if logon_type == "10":
        protocol = "RDP"
        port = 3389
    elif logon_type == "3":
        protocol = "SMB/Network"
        port = 445
    elif logon_type == "2":
        protocol = "Interactive"

    record = {
        "timestamp": timestamp,
        "source_ip": source_ip if source_ip and source_ip != "-" else "unknown",
        "destination_ip": local_ip,
        "event_type": mapping["event_type"],
        "user": target_user or "unknown",
        "status": mapping["status"],
        "message": messages.get(event_id, ""),
        "event_id": event_id,
        "logon_type": logon_type,
        "label": mapping["label"],
    }
    if port:
        record["port"] = port
    if protocol:
        record["protocol"] = protocol

    return record


def get_local_ip() -> str:
    """Get the local machine's primary IP."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch 'Loopback' } | Select-Object -First 1).IPAddress"],
            capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip() or "192.168.1.x"
    except Exception:
        return "192.168.1.x"


def run_ingester(log_name: str, hours: int, output_path: str) -> list[dict]:
    """Run the PowerShell query and parse results."""
    event_ids = list(EVENT_MAP.keys())
    ps_query = build_powershell_query(log_name, event_ids, hours)

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_query],
            capture_output=True, text=True, timeout=60
        )
    except subprocess.TimeoutExpired:
        print(f"[ERROR] PowerShell query timed out after 60s", file=sys.stderr)
        return []

    if result.returncode != 0:
        stderr = result.stderr.strip()
        if "access" in stderr.lower() or "denied" in stderr.lower():
            print(f"[ERROR] Access denied reading '{log_name}' log. Try running as Administrator.", file=sys.stderr)
        else:
            print(f"[ERROR] PowerShell error: {stderr}", file=sys.stderr)
        return []

    stdout = result.stdout.strip()
    if stdout == "NO_EVENTS" or not stdout:
        print(f"[INFO] No events found in {log_name} log for the last {hours} hour(s).")
        return []

    # Split by marker and parse each event XML
    events = []
    local_ip = get_local_ip()
    raw_events = stdout.split("===EVENT===")

    for raw in raw_events:
        raw = raw.strip()
        if not raw:
            continue
        parsed = parse_event(raw, local_ip)
        if parsed:
            events.append(parsed)

    return events


def save_events(events: list[dict], output_path: str, max_keep: int = 500):
    """Append events to output file, keeping only the last max_keep entries."""
    existing = []
    if os.path.exists(output_path):
        try:
            with open(output_path, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except (json.JSONDecodeError, IOError):
            existing = []

    existing.extend(events)
    existing = existing[-max_keep:]

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2)

    print(f"[INFO] Saved {len(events)} new events to {output_path} (total: {len(existing)})")


def main():
    parser = argparse.ArgumentParser(description="Windows Event Log Ingester for AI Cyber Defense Pipeline")
    parser.add_argument("--hours", type=int, default=1, help="Hours of events to query (default: 1)")
    parser.add_argument("--output", type=str, default=None, help="Output JSON file path")
    parser.add_argument("--log", type=str, default="Security", choices=["Security", "Application", "System"],
                        help="Windows log to query (default: Security)")
    parser.add_argument("--dry-run", action="store_true", help="Print events without saving")
    args = parser.parse_args()

    # Default output path
    if args.output is None:
        script_dir = Path(__file__).resolve().parent.parent
        args.output = str(script_dir / "data" / "windows_events.json")

    print(f"[INFO] Querying '{args.log}' log for last {args.hours} hour(s)...")

    # Try Security log first; if access denied, suggest admin or fallback
    events = run_ingester(args.log, args.hours, args.output)

    if not events and args.log == "Security":
        print(f"\n[WARN] No events from Security log. This usually requires Administrator privileges.")
        print(f"[HINT] Re-run as admin, or try: python {__file__} --log Application")
        # Optionally auto-fallback
        print(f"\n[INFO] Trying Application log as fallback...")
        events = run_ingester("Application", args.hours, args.output)

    if events:
        print(f"\n[INFO] Parsed {len(events)} events:")
        for evt in events[:5]:
            print(f"  [{evt['event_id']}] {evt['label']}: {evt['message'][:100]}")
        if len(events) > 5:
            print(f"  ... and {len(events) - 5} more")

        if not args.dry_run:
            save_events(events, args.output)
        else:
            print("\n[DRY RUN] Events not saved.")
    else:
        print("[INFO] No relevant events found.")


if __name__ == "__main__":
    main()
