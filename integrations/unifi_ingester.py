"""UniFi Cloud API security log ingester.

Fetches security events from UniFi Cloud API and normalizes them
to the format expected by the ai-cyber-defense LangGraph pipeline.

Usage:
    python -m integrations.unifi_ingester --since 30
    python -m integrations.unifi_ingester --since 60 --output data/my_events.json
"""

import argparse
import json
import os
import time
from datetime import datetime, timedelta, timezone

from integrations.unifi_api import fetch_security_events, fetch_active_clients


def normalize_unifi_event(event):
    """Map a UniFi API event to the pipeline's expected format.
    
    UniFi event structure (varies by type):
    {
        "event_id": "...",
        "timestamp": 1710000000000,  # epoch ms
        "type": "EVT_ADG_NETWORK_CONNECT",
        "subtype": "...",
        "key": "...",
        "msg": "Client connected",
        "src": "192.168.1.100",
        "dst": "192.168.1.1",
        "hostname": "DEVICE-NAME",
        "mac": "aa:bb:cc:dd:ee:ff",
        "network": "LAN",
        "site_id": "..."
    }
    
    Pipeline expected format:
    {
        "timestamp": "2026-03-20T05:30:00Z",
        "source_ip": "192.168.1.100",
        "destination_ip": "10.0.0.5",
        "event_type": "login_attempt",
        "user": "admin",
        "status": "failed",
        "message": "...",
        "port": 22,
        "protocol": "SSH"
    }
    """
    ts = event.get("timestamp", 0)
    if ts and ts > 1e12:
        ts = ts / 1000  # ms to seconds
    
    evt_type_raw = event.get("type", "")
    msg = event.get("msg", "")
    src_ip = event.get("src", event.get("source_ip", ""))
    dst_ip = event.get("dst", event.get("dest_ip", event.get("destination_ip", "")))
    
    # Classify UniFi event types into pipeline event types
    event_type = "unknown"
    status = "info"
    port = None
    protocol = None
    user = event.get("user", event.get("hostname", ""))
    
    evt_lower = evt_type_raw.lower()
    msg_lower = msg.lower()
    
    # Firewall / blocked
    if "blocked" in evt_lower or "blocked" in msg_lower or "deny" in evt_lower:
        event_type = "connection_blocked"
        status = "blocked"
    # DHCP
    elif "dhcp" in evt_lower or "dhcp" in msg_lower:
        event_type = "dhcp_event"
    # WiFi connect/disconnect
    elif "connect" in evt_lower and ("wifi" in evt_lower or "wireless" in evt_lower or "wlan" in evt_lower):
        event_type = "wifi_connect"
        status = "success"
    elif "disconnect" in evt_lower:
        event_type = "device_disconnected"
        status = "disconnected"
    # VPN
    elif "vpn" in evt_lower:
        event_type = "vpn_event"
    # Gateway / routing
    elif "gateway" in evt_lower or "route" in evt_lower:
        event_type = "routing_event"
    # Suspicious patterns
    elif "intrusion" in evt_lower or "ids" in evt_lower or "ips" in evt_lower:
        event_type = "intrusion_detected"
        status = "alert"
    # Port scan (detected from rapid connection attempts)
    elif "port_scan" in evt_lower or "scan" in msg_lower:
        event_type = "port_scan"
        status = "alert"
    # Auth failures
    elif "auth" in evt_lower and ("fail" in evt_lower or "denied" in evt_lower):
        event_type = "authentication_failure"
        status = "failed"
    # Default: network event
    else:
        event_type = "network_event"
    
    # Try to extract port from message
    if "port" in msg_lower:
        import re
        port_match = re.search(r'port[:\s]+(\d+)', msg_lower)
        if port_match:
            port = int(port_match.group(1))
    
    normalized = {
        "timestamp": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts else "",
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "event_type": event_type,
        "user": user,
        "status": status,
        "message": msg or evt_type_raw,
        "raw_type": evt_type_raw,
        "protocol": protocol,
    }
    if port:
        normalized["port"] = port
    
    return normalized


def run_ingester(since_minutes=30, output_path=None):
    """Fetch and normalize UniFi events."""
    if not output_path:
        output_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "data", "live_events.json"
        )
    
    since_ms = int((time.time() - since_minutes * 60) * 1000)
    
    print(f"Fetching UniFi events from last {since_minutes} minutes...")
    
    try:
        raw_events = fetch_security_events(since_ms=since_ms)
    except Exception as e:
        print(f"Error fetching events: {e}")
        raw_events = []
    
    if not raw_events:
        print("No events returned from UniFi API.")
        return []
    
    normalized = []
    for evt in raw_events:
        try:
            norm = normalize_unifi_event(evt)
            normalized.append(norm)
        except Exception as e:
            print(f"Warning: could not normalize event {evt.get('event_id', '?')}: {e}")
    
    # Load existing events and append (keep last 500)
    existing = []
    if os.path.exists(output_path):
        try:
            with open(output_path, "r") as f:
                existing = json.load(f)
        except (json.JSONDecodeError, IOError):
            existing = []
    
    combined = existing + normalized
    combined = combined[-500:]  # keep last 500
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(combined, f, indent=2)
    
    print(f"Normalized {len(normalized)} events. Total stored: {len(combined)}")
    
    # Summary
    event_types = {}
    for e in normalized:
        t = e["event_type"]
        event_types[t] = event_types.get(t, 0) + 1
    
    if event_types:
        print("\nEvent breakdown:")
        for t, count in sorted(event_types.items(), key=lambda x: -x[1]):
            print(f"  {t}: {count}")
    
    return normalized


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="UniFi security log ingester")
    parser.add_argument("--since", type=int, default=30, help="Minutes ago to fetch events")
    parser.add_argument("--output", type=str, default=None, help="Output JSON file path")
    args = parser.parse_args()
    run_ingester(since_minutes=args.since, output_path=args.output)
