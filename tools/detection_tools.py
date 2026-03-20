"""Tools for detecting threats: pattern matching, anomaly detection, threat intelligence."""

import json
import re
from collections import Counter, defaultdict
from langchain_core.tools import tool


# Known malicious IP ranges (simulated threat intel)
KNOWN_MALICIOUS_IPS = {
    "203.0.113.50", "203.0.113.51", "198.51.100.23", "198.51.100.24",
    "45.33.32.156", "91.189.92.10", "185.220.101.1", "185.220.101.2",
}

# Known malicious user agents / signatures
KNOWN_ATTACK_SIGNATURES = {
    "nikto", "sqlmap", "nmap", "masscan", "hydra", "dirbuster",
    "wpscan", "metasploit", "cobalt strike",
}

# Sensitive file patterns for data exfiltration detection
SENSITIVE_FILE_PATTERNS = {
    "payroll", "salary", "ssn", "social_security", "passwd", "shadow",
    "credit_card", "bank_account", "confidential", "secret", "private_key",
    "employee", "hr_records", "medical", "hipaa", "pii",
}

# Ransomware indicators
RANSOMWARE_PATTERNS = {
    "ransom", "decrypt", "bitcoin", "monero", "wallet", "payment",
    "encrypted", ".locked", ".crypto", ".enc", ".crypt",
    "readme_decrypt", "restore_files", "how_to_decrypt",
}

# Suspicious executable/service patterns
MALWARE_PATTERNS = {
    "cryptolocker", "wannacry", "ryuk", "lockbit", "blackcat",
    "cobaltstrike", "meterpreter", "beacon", "shell", "backdoor",
    "keylogger", "stealer", "miner", "rat", "trojan",
}

# Large data transfer thresholds (in MB)
DATA_EXFIL_THRESHOLD_MB = 50  # Flag transfers > 50MB to external IPs


@tool
def pattern_detector(events_json: str) -> str:
    """Detect known attack patterns in normalized events using rule-based logic.

    Detects: brute force, credential stuffing, port scanning, privilege escalation,
    and known attack tool signatures.

    Args:
        events_json: JSON string of normalized events.

    Returns:
        JSON string of detected threat patterns.
    """
    events = json.loads(events_json)
    if isinstance(events, dict):
        events = events.get("normalized_events", events.get("events", []))

    threats = []

    # --- Brute Force Detection ---
    # Group failed logins by (source_ip, target_user) in sliding windows
    failed_logins = defaultdict(list)
    for e in events:
        if e.get("event_type") in ("login_attempt", "login_failure", "authentication_failure") and e.get("status") == "failed":
            key = (e.get("source_ip", ""), e.get("user", ""))
            failed_logins[key].append(e)

    for (ip, user), attempts in failed_logins.items():
        if len(attempts) >= 5:
            threats.append({
                "type": "brute_force",
                "severity_hint": "high",
                "source_ip": ip,
                "target_user": user,
                "attempt_count": len(attempts),
                "description": f"Brute force detected: {len(attempts)} failed logins from {ip} targeting user '{user}'",
                "evidence_indices": [a.get("_index", -1) for a in attempts],
            })
        elif len(attempts) >= 3:
            threats.append({
                "type": "brute_force_attempt",
                "severity_hint": "medium",
                "source_ip": ip,
                "target_user": user,
                "attempt_count": len(attempts),
                "description": f"Possible brute force: {len(attempts)} failed logins from {ip} targeting user '{user}'",
                "evidence_indices": [a.get("_index", -1) for a in attempts],
            })

    # --- Credential Stuffing Detection ---
    # Many different users targeted from same IP
    ip_users = defaultdict(set)
    for e in events:
        if e.get("status") == "failed" and e.get("event_type") in ("login_attempt", "login_failure", "authentication_failure"):
            ip_users[e.get("source_ip", "")].add(e.get("user", ""))

    for ip, users in ip_users.items():
        if len(users) >= 3:
            threats.append({
                "type": "credential_stuffing",
                "severity_hint": "high",
                "source_ip": ip,
                "targeted_users": list(users),
                "user_count": len(users),
                "description": f"Credential stuffing from {ip}: {len(users)} different users targeted ({', '.join(sorted(users))})",
            })

    # --- Port Scanning Detection ---
    ip_ports = defaultdict(set)
    for e in events:
        if e.get("event_type") in ("network_connection", "port_scan", "firewall_block"):
            port = e.get("port") or e.get("destination_port")
            if port:
                ip_ports[e.get("source_ip", "")].add(port)

    for ip, ports in ip_ports.items():
        if len(ports) >= 5:
            threats.append({
                "type": "port_scan",
                "severity_hint": "high",
                "source_ip": ip,
                "ports_scanned": sorted(ports),
                "port_count": len(ports),
                "description": f"Port scan from {ip}: {len(ports)} distinct ports probed ({sorted(ports)[:10]})",
            })

    # --- Privilege Escalation Detection ---
    for e in events:
        if e.get("event_type") in ("privilege_escalation", "sudo_command"):
            threats.append({
                "type": "privilege_escalation",
                "severity_hint": "critical",
                "source_ip": e.get("source_ip", ""),
                "user": e.get("user", ""),
                "description": f"Privilege escalation by user '{e.get('user', '')}' from {e.get('source_ip', '')}: {e.get('message', '')}",
                "evidence_indices": [e.get("_index", -1)],
            })

    # --- Known Attack Tool Signatures ---
    for e in events:
        msg = (e.get("message", "") + " " + e.get("user_agent", "")).lower()
        for sig in KNOWN_ATTACK_SIGNATURES:
            if sig in msg:
                threats.append({
                    "type": "attack_tool_detected",
                    "severity_hint": "critical",
                    "source_ip": e.get("source_ip", ""),
                    "signature": sig,
                    "description": f"Known attack tool '{sig}' detected from {e.get('source_ip', '')}",
                    "evidence_indices": [e.get("_index", -1)],
                })
                break

    # --- Sensitive File Access Detection ---
    for e in events:
        if e.get("event_type") in ("file_access", "file_modify", "file_delete"):
            msg = (e.get("message", "") + " " + e.get("file", "")).lower()
            for pattern in SENSITIVE_FILE_PATTERNS:
                if pattern in msg:
                    sip = e.get("source_ip", "")
                    is_external = sip in KNOWN_MALICIOUS_IPS or not (
                        sip.startswith("10.") or sip.startswith("192.168.") or sip.startswith("172.")
                    )
                    severity = "critical" if is_external else "medium"
                    threats.append({
                        "type": "sensitive_file_access",
                        "severity_hint": severity,
                        "source_ip": sip,
                        "user": e.get("user", ""),
                        "file_pattern": pattern,
                        "from_external_ip": is_external,
                        "description": (
                            f"Sensitive file access ({pattern}) by '{e.get('user', '')}' from "
                            f"{'EXTERNAL/MALICIOUS' if is_external else 'internal'} IP {sip}: {e.get('message', '')}"
                        ),
                        "evidence_indices": [e.get("_index", -1)],
                    })
                    break

    # --- Post-Exploitation Chain Detection ---
    # Privilege escalation followed by sensitive file modifications from same IP
    escalation_ips = set()
    escalation_users = set()
    for e in events:
        if e.get("event_type") == "privilege_escalation":
            escalation_ips.add(e.get("source_ip", ""))
            escalation_users.add(e.get("user", ""))

    post_exploit_mods = []
    for e in events:
        if e.get("event_type") == "file_modify" and e.get("source_ip", "") in escalation_ips:
            msg = e.get("message", "").lower()
            # Flag modifications to system files or from escalated sessions
            if any(sf in msg for sf in ("/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh",
                                         "authorized_keys", ".bashrc", "crontab", "/root/")):
                post_exploit_mods.append(e)

    if post_exploit_mods:
        threats.append({
            "type": "post_exploitation_chain",
            "severity_hint": "critical",
            "source_ips": list(escalation_ips),
            "users": list(escalation_users),
            "modified_files": [e.get("message", "") for e in post_exploit_mods],
            "modification_count": len(post_exploit_mods),
            "description": (
                f"Post-exploitation chain: privilege escalation from {list(escalation_ips)} "
                f"followed by {len(post_exploit_mods)} system file modifications "
                f"({', '.join(e.get('message', '') for e in post_exploit_mods[:3])})"
            ),
            "evidence_indices": [e.get("_index", -1) for e in post_exploit_mods],
        })

    # --- Intrusion Attempt Detection ---
    intrusion_by_ip = defaultdict(list)
    for e in events:
        if e.get("event_type") == "intrusion_attempt":
            intrusion_by_ip[e.get("source_ip", "")].append(e)

    for ip, attempts in intrusion_by_ip.items():
        threats.append({
            "type": "intrusion_attempt",
            "severity_hint": "critical" if ip in KNOWN_MALICIOUS_IPS else "high",
            "source_ip": ip,
            "attempt_count": len(attempts),
            "description": (
                f"{len(attempts)} intrusion attempt(s) from {ip}: "
                f"{', '.join(a.get('message', '')[:60] for a in attempts[:3])}"
            ),
            "evidence_indices": [a.get("_index", -1) for a in attempts],
        })

    # --- Ransomware / Malware Detection ---
    for e in events:
        msg = e.get("message", "").lower()
        etype = e.get("event_type", "")
        # Ransomware file patterns
        if etype in ("file_modify", "file_create", "service_start"):
            for pattern in RANSOMWARE_PATTERNS:
                if pattern in msg:
                    threats.append({
                        "type": "ransomware_activity",
                        "severity_hint": "critical",
                        "source_ip": e.get("source_ip", ""),
                        "user": e.get("user", ""),
                        "pattern": pattern,
                        "description": (
                            f"Ransomware indicator detected: {e.get('message', '')}"
                        ),
                        "evidence_indices": [e.get("_index", -1)],
                    })
                    break
            # Malware executable patterns
            for pattern in MALWARE_PATTERNS:
                if pattern in msg:
                    threats.append({
                        "type": "malware_detected",
                        "severity_hint": "critical",
                        "source_ip": e.get("source_ip", ""),
                        "user": e.get("user", ""),
                        "pattern": pattern,
                        "description": (
                            f"Malware signature '{pattern}' detected: {e.get('message', '')}"
                        ),
                        "evidence_indices": [e.get("_index", -1)],
                    })
                    break

    # --- Mass File Encryption Detection ---
    # Detect rapid file modifications (ransomware behavior)
    file_mods_by_source = defaultdict(list)
    for e in events:
        if e.get("event_type") == "file_modify":
            file_mods_by_source[e.get("source_ip", "")].append(e)

    for ip, mods in file_mods_by_source.items():
        total_files = len(mods)
        # Also check for "X files" pattern in any message (e.g., "1,247 files modified")
        for m in mods:
            count_match = re.search(r"(\d[\d,]*)\s+files?", m.get("message", ""), re.IGNORECASE)
            if count_match:
                total_files = max(total_files, int(count_match.group(1).replace(",", "")))

        if total_files >= 5:  # 5+ files modified from same source
            msg = mods[0].get("message", "").lower()
            # Check for encryption/mass patterns
            if any(w in msg for w in ("encrypted", "modified", "changed", "locked", "mass", "multiple")):
                threats.append({
                    "type": "mass_file_modification",
                    "severity_hint": "critical",
                    "source_ip": ip,
                    "user": mods[0].get("user", ""),
                    "file_count": total_files,
                    "description": (
                        f"Mass file modification from {ip}: {total_files} files modified. "
                        f"Possible ransomware: {mods[0].get('message', '')[:80]}"
                    ),
                    "evidence_indices": [m.get("_index", -1) for m in mods],
                })

    # --- Data Exfiltration Detection ---
    # Large outbound data transfers to external IPs
    for e in events:
        if e.get("event_type") in ("network_connection", "data_transfer", "file_upload"):
            msg = e.get("message", "")
            dest_ip = e.get("destination_ip", "")
            # Check if destination is external (not private ranges)
            is_external = not (
                dest_ip.startswith("10.") or
                dest_ip.startswith("192.168.") or
                dest_ip.startswith("172.") or
                dest_ip == "10.0.1.1"  # gateway
            )
            if is_external and dest_ip:
                # Look for size indicators in message (e.g., "450MB sent", "85MB uploaded")
                size_match = re.search(r"(\d+(?:\.\d+)?)\s*MB", msg, re.IGNORECASE)
                if size_match:
                    size_mb = float(size_match.group(1))
                    if size_mb >= DATA_EXFIL_THRESHOLD_MB:
                        threats.append({
                            "type": "data_exfiltration",
                            "severity_hint": "critical" if dest_ip in KNOWN_MALICIOUS_IPS else "high",
                            "source_ip": e.get("source_ip", ""),
                            "destination_ip": dest_ip,
                            "size_mb": size_mb,
                            "user": e.get("user", ""),
                            "description": (
                                f"Large data transfer ({size_mb}MB) to external IP {dest_ip}: {msg[:100]}"
                            ),
                            "evidence_indices": [e.get("_index", -1)],
                        })

    return json.dumps({"threats": threats, "threat_count": len(threats)})


@tool
def anomaly_detector(events_json: str) -> str:
    """Detect statistical anomalies in event patterns.

    Analyzes: off-hours activity, geographic anomalies, unusual event volume spikes,
    and rare event type occurrences.

    Args:
        events_json: JSON string of normalized events.

    Returns:
        JSON string of detected anomalies.
    """
    events = json.loads(events_json)
    if isinstance(events, dict):
        events = events.get("normalized_events", events.get("events", []))

    anomalies = []

    # --- Off-Hours Login Detection ---
    # Business hours: 6 AM - 22 PM; off-hours logins are suspicious
    for e in events:
        hour = e.get("hour")
        if hour is not None and e.get("event_type") in ("login_attempt", "login_success") and e.get("status") == "success":
            if hour < 6 or hour >= 22:
                anomalies.append({
                    "type": "off_hours_login",
                    "severity_hint": "medium",
                    "user": e.get("user", ""),
                    "source_ip": e.get("source_ip", ""),
                    "hour": hour,
                    "description": f"Off-hours login by '{e.get('user', '')}' at {hour}:00 from {e.get('source_ip', '')}",
                    "evidence_indices": [e.get("_index", -1)],
                })

    # --- Geographic Anomaly Detection ---
    # Same user logging in from multiple very different IPs (possible impossible travel)
    user_ips = defaultdict(set)
    for e in events:
        if e.get("event_type") in ("login_attempt", "login_success") and e.get("status") == "success":
            user_ips[e.get("user", "")].add(e.get("source_ip", ""))

    for user, ips in user_ips.items():
        # Flag if user logs in from both internal and external IPs
        internal = [ip for ip in ips if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.")]
        external = [ip for ip in ips if ip not in internal]
        if internal and external:
            anomalies.append({
                "type": "geo_anomaly",
                "severity_hint": "high",
                "user": user,
                "internal_ips": internal,
                "external_ips": external,
                "description": f"Geographic anomaly: user '{user}' logged in from both internal ({internal}) and external ({external}) IPs",
            })
        if len(external) >= 2:
            anomalies.append({
                "type": "impossible_travel",
                "severity_hint": "high",
                "user": user,
                "ips": list(external),
                "description": f"Possible impossible travel: user '{user}' logged in from {len(external)} different external IPs: {list(external)}",
            })

    # --- Volume Spike Detection ---
    # If any single IP generates >20% of total events, flag it
    # Skip IPs that are already explained by port scans or brute force (reduces noise)
    ip_counts = Counter(e.get("source_ip", "") for e in events)
    total = len(events)
    # Collect IPs already flagged for port scan or brute force patterns
    high_volume_explained_ips = set()
    for e in events:
        ip = e.get("source_ip", "")
        if e.get("event_type") in ("network_connection", "port_scan", "firewall_block"):
            high_volume_explained_ips.add(ip)
        if e.get("event_type") in ("login_attempt", "login_failure", "authentication_failure") and e.get("status") == "failed":
            high_volume_explained_ips.add(ip)
    for ip, count in ip_counts.items():
        if total > 5 and count / total > 0.20 and ip not in high_volume_explained_ips:
            anomalies.append({
                "type": "volume_spike",
                "severity_hint": "medium",
                "source_ip": ip,
                "event_count": count,
                "percentage": round(count / total * 100, 1),
                "description": f"Volume spike: {ip} generated {count}/{total} events ({round(count / total * 100, 1)}% of total)",
            })

    # --- Rare Event Types ---
    type_counts = Counter(e.get("event_type", "") for e in events)
    for etype, count in type_counts.items():
        if count == 1 and etype in ("malware_detected", "intrusion_attempt", "config_change"):
            anomalies.append({
                "type": "rare_critical_event",
                "severity_hint": "high",
                "event_type": etype,
                "description": f"Rare critical event type detected: '{etype}' occurred only {count} time(s)",
            })

    return json.dumps({"anomalies": anomalies, "anomaly_count": len(anomalies)})


@tool
def threat_lookup(events_json: str) -> str:
    """Check source IPs against known threat intelligence feeds.

    Args:
        events_json: JSON string of normalized events.

    Returns:
        JSON string of IPs that match known malicious sources.
    """
    events = json.loads(events_json)
    if isinstance(events, dict):
        events = events.get("normalized_events", events.get("events", []))

    hits = []
    checked_ips = set()
    for e in events:
        ip = e.get("source_ip", "")
        if ip and ip not in checked_ips:
            checked_ips.add(ip)
            if ip in KNOWN_MALICIOUS_IPS:
                hits.append({
                    "type": "known_malicious_ip",
                    "severity_hint": "critical",
                    "source_ip": ip,
                    "description": f"IP {ip} matches known malicious threat intelligence feed",
                    "intel_source": "internal_threat_db",
                })

    return json.dumps({"threat_intel_hits": hits, "ips_checked": len(checked_ips), "hits_count": len(hits)})
