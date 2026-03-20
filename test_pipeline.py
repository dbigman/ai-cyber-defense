"""Quick test of the pipeline tools directly."""
import json, os
from dotenv import load_dotenv
load_dotenv()

from tools.ingestion_tools import parse_log, validate_entry, normalize_data
from tools.detection_tools import pattern_detector, anomaly_detector, threat_lookup

with open("data/apt_attack_logs.json") as f:
    raw = f.read()

# Ingest
parsed = json.loads(parse_log.invoke(raw))
validated = json.loads(validate_entry.invoke(json.dumps(parsed)))
normalized = json.loads(normalize_data.invoke(json.dumps(validated)))
events = normalized["normalized_events"]
print(f"Normalized events: {len(events)}")

# Detect
events_json = json.dumps({"normalized_events": events})
patterns = json.loads(pattern_detector.invoke(events_json))
anomalies = json.loads(anomaly_detector.invoke(events_json))
threats = json.loads(threat_lookup.invoke(events_json))

print(f"\nPatterns: {patterns['threat_count']}")
for t in patterns["threats"]:
    print(f"  [{t['type']}] {t['description'][:100]}")

print(f"\nAnomalies: {anomalies['anomaly_count']}")
for a in anomalies["anomalies"]:
    print(f"  [{a['type']}] {a['description'][:100]}")

print(f"\nThreat intel: {threats['hits_count']}")
for h in threats["threat_intel_hits"]:
    print(f"  [{h['type']}] {h['description'][:100]}")

all_threats = patterns["threats"] + anomalies["anomalies"] + threats["threat_intel_hits"]
print(f"\nTotal: {len(all_threats)} findings")

# Group by type
from collections import Counter
type_counts = Counter(t['type'] for t in all_threats)
print("\nBy type:")
for t, c in sorted(type_counts.items(), key=lambda x: -x[1]):
    print(f"  {t}: {c}")
