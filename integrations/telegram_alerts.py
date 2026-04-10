"""Send Telegram alerts for high-severity security findings."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests

from integrations.alert_rules import AlertRules

logger = logging.getLogger(__name__)

SEVERITY_EMOJI = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🟢",
}

DEFAULT_CHAT_ID = "2112108642"
DEDUP_FILE = Path("data/sent_alerts.json")
COOLDOWN_SECONDS = 30 * 60  # 30 minutes


def _load_sent_alerts() -> dict:
    if DEDUP_FILE.exists():
        try:
            return json.loads(DEDUP_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_sent_alerts(data: dict) -> None:
    DEDUP_FILE.parent.mkdir(parents=True, exist_ok=True)
    DEDUP_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _event_signature(finding: dict) -> str:
    """Stable hash for dedup — based on description + source IP + event type."""
    raw = f"{finding.get('event_type', '')}|{finding.get('source_ip', '')}|{finding.get('description', '')}"
    return hashlib.md5(raw.encode()).hexdigest()


def _is_duplicate(sig: str, sent: dict) -> bool:
    ts = sent.get(sig, 0)
    return (time.time() - ts) < COOLDOWN_SECONDS


def _format_alert(finding: dict) -> str:
    emoji = SEVERITY_EMOJI.get(finding.get("severity", ""), "⚠️")
    severity = finding.get("severity", "Unknown")
    event_type = finding.get("event_type", "Unknown")
    src = finding.get("source_ip", "N/A")
    desc = finding.get("description", "No description")
    risk = finding.get("risk_score", "?")
    action = finding.get("recommended_action", finding.get("recommended_actions", "Review immediately"))

    return (
        f"{emoji} *{severity} Security Alert*\n"
        f"*Type:* {event_type}\n"
        f"*Source:* `{src}`\n"
        f"*Risk Score:* {risk}/10\n"
        f"*Description:* {desc}\n"
        f"*Action:* {action}"
    )


def send_telegram(message: str, chat_id: str = DEFAULT_CHAT_ID) -> bool:
    """Send a message via Telegram Bot API. Returns True on success."""
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        logger.error("TELEGRAM_BOT_TOKEN not set — skipping alert")
        return False

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "Markdown",
    }
    try:
        resp = requests.post(url, json=payload, timeout=10)
        resp.raise_for_status()
        logger.info("Telegram alert sent to %s", chat_id)
        return True
    except requests.RequestException as exc:
        logger.error("Telegram send failed: %s", exc)
        return False


def send_alerts(
    pipeline_result: dict,
    rules: Optional[AlertRules] = None,
    chat_id: str = DEFAULT_CHAT_ID,
) -> int:
    """Filter findings and send Telegram alerts. Returns count of alerts sent."""
    rules = rules or AlertRules()
    classifications = pipeline_result.get("classifications", [])
    if not classifications:
        logger.info("No classifications found in pipeline result")
        return 0

    # Classifications may be list of dicts with "findings" key, or flat list
    all_findings: list[dict] = []
    for item in classifications:
        if isinstance(item, dict) and "findings" in item:
            all_findings.extend(item["findings"])
        elif isinstance(item, dict):
            all_findings.append(item)

    now = datetime.now()
    sent_db = _load_sent_alerts()
    sent_count = 0

    for finding in all_findings:
        if not rules.should_alert(finding, now):
            continue

        sig = _event_signature(finding)
        if _is_duplicate(sig, sent_db):
            logger.debug("Skipping duplicate alert: %s", sig[:8])
            continue

        msg = _format_alert(finding)
        if send_telegram(msg, chat_id):
            sent_db[sig] = time.time()
            sent_count += 1

    if sent_count:
        # Prune entries older than 24h to keep file small
        cutoff = time.time() - 86400
        sent_db = {k: v for k, v in sent_db.items() if v > cutoff}
        _save_sent_alerts(sent_db)

    return sent_count
