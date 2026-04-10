"""Run the full pipeline with optional Telegram alerting.

Usage:
    python -m integrations.run_with_alerts --input data/logs.json --alert
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys

from dotenv import load_dotenv

load_dotenv()

# Ensure project root is on sys.path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser(description="AI Cyber Defense pipeline with Telegram alerts")
    parser.add_argument("--input", "-i", default="data/sample_security_logs.json",
                        help="Path to security log file (JSON)")
    parser.add_argument("--output", "-o", default="output/report.md",
                        help="Path to save the report")
    parser.add_argument("--model", "-m", default="deepseek-chat",
                        help="DeepSeek model name")
    parser.add_argument("--alert", action="store_true",
                        help="Send Telegram alerts for High/Critical findings")
    parser.add_argument("--alert-config", default=None,
                        help="Path to alert rules JSON config")
    parser.add_argument("--chat-id", default="2112108642",
                        help="Telegram chat ID for alerts")
    args = parser.parse_args()

    if not os.environ.get("DEEPSEEK_API_KEY"):
        print("Error: DEEPSEEK_API_KEY not set. Copy .env.example to .env and add your key.")
        sys.exit(1)

    # ── Run pipeline (same as run.py) ──────────────────────────────────
    print(f"Reading logs from {args.input}...")
    with open(args.input, "r") as f:
        logs = f.read()

    data = json.loads(logs)
    print(f"Loaded {len(data)} log events.")

    from agents.graph import run_pipeline

    print(f"Running pipeline with model: {args.model}")
    print("=" * 60)
    result = run_pipeline(logs, model_name=args.model)

    print("=" * 60)
    print(f"Pipeline complete in {result['metadata'].get('total_time', '?')}s")
    print(f"  Events processed: {len(result.get('normalized_events', []))}")
    print(f"  Threats detected: {len(result.get('threats', []))}")
    print(f"  Incidents classified: {len(result.get('classifications', []))}")

    # Save report
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(result.get("report", "No report generated."))
    print(f"Report saved to {args.output}")

    # ── Send alerts ────────────────────────────────────────────────────
    if args.alert:
        try:
            from integrations.alert_rules import AlertRules
            from integrations.telegram_alerts import send_alerts

            rules = AlertRules()
            if args.alert_config:
                rules = AlertRules.from_json_file(args.alert_config)

            count = send_alerts(result, rules=rules, chat_id=args.chat_id)
            print(f"Sent {count} Telegram alert(s)")
        except Exception as exc:
            logger.error("Alerting failed (pipeline output preserved): %s", exc)
    else:
        print("Alerting disabled. Use --alert to enable.")


if __name__ == "__main__":
    main()
