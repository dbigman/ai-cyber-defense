"""Simple scheduler for running ingesters on interval.

Usage:
    python -m integrations.scheduler --interval 15 --ingester unifi
    python -m integrations.scheduler --interval 30 --ingester windows
"""

import argparse
import time
import subprocess
import sys
import os


def run_ingester(name, since_minutes=15):
    """Run a named ingester module."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    if name == "unifi":
        cmd = [sys.executable, "-m", "integrations.unifi_ingester", "--since", str(since_minutes)]
    elif name == "windows":
        cmd = [sys.executable, "-m", "integrations.windows_event_ingester", "--hours", str(max(1, since_minutes // 60))]
    else:
        print(f"Unknown ingester: {name}")
        return False
    
    result = subprocess.run(cmd, cwd=base_dir, capture_output=True, text=True)
    
    if result.stdout:
        print(result.stdout.strip())
    if result.stderr:
        print(f"STDERR: {result.stderr.strip()}")
    
    return result.returncode == 0


def main():
    parser = argparse.ArgumentParser(description="Run ingesters on schedule")
    parser.add_argument("--ingester", type=str, default="unifi", choices=["unifi", "windows"], help="Which ingester to run")
    parser.add_argument("--interval", type=int, default=15, help="Run interval in minutes")
    parser.add_argument("--since", type=int, default=15, help="Minutes of data to fetch each run")
    parser.add_argument("--once", action="store_true", help="Run once and exit")
    args = parser.parse_args()
    
    print(f"Scheduler: {args.ingester} every {args.interval} minutes")
    
    if args.once:
        run_ingester(args.ingester, args.since)
        return
    
    while True:
        print(f"\n--- Run at {time.strftime('%Y-%m-%d %H:%M:%S')} ---")
        run_ingester(args.ingester, args.since)
        print(f"Next run in {args.interval} minutes...")
        time.sleep(args.interval * 60)


if __name__ == "__main__":
    main()
