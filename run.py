"""CLI entry point for the AI Cyber Defense pipeline."""

import argparse
import json
import os
import sys

from dotenv import load_dotenv

load_dotenv()


def main():
    parser = argparse.ArgumentParser(description="AI Cyber Defense Multi-Agent System")
    parser.add_argument("--input", "-i", default="data/sample_security_logs.json", help="Path to security log file (JSON)")
    parser.add_argument("--output", "-o", default="output/report.md", help="Path to save the report")
    parser.add_argument("--model", "-m", default="gpt-4o-mini", help="OpenAI model name")
    args = parser.parse_args()

    if not os.environ.get("OPENAI_API_KEY"):
        print("Error: OPENAI_API_KEY not set. Copy .env.example to .env and add your key.")
        sys.exit(1)

    # Read input logs
    print(f"Reading logs from {args.input}...")
    with open(args.input, "r") as f:
        logs = f.read()

    data = json.loads(logs)
    print(f"Loaded {len(data)} log events.")

    # Run the pipeline
    from agents.graph import run_pipeline

    print(f"Running pipeline with model: {args.model}")
    print("=" * 60)
    print("[1/4] Ingest Agent: Parsing and normalizing logs...")
    result = run_pipeline(logs, model_name=args.model)

    # Print summary
    print("=" * 60)
    print(f"Pipeline complete in {result['metadata'].get('total_time', '?')}s")
    print(f"  Events processed: {len(result.get('normalized_events', []))}")
    print(f"  Threats detected: {len(result.get('threats', []))}")
    print(f"  Incidents classified: {len(result.get('classifications', []))}")
    print()

    # Save report
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        f.write(result.get("report", "No report generated."))
    print(f"Report saved to {args.output}")

    # Print agent reasoning if available
    reasoning = result.get("agent_reasoning", {})
    if reasoning:
        print("\n--- Agent Reasoning ---")
        for agent, text in reasoning.items():
            if text:
                print(f"\n[{agent.upper()}]")
                print(text[:500] + ("..." if len(text) > 500 else ""))


if __name__ == "__main__":
    main()
