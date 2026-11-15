import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "datasets"
REPORTS = ROOT / "reports"
REPORTS.mkdir(parents=True, exist_ok=True)


def read_csv(filename):
    with (DATA / filename).open(
        "r", encoding="utf-8-sig", newline=""
    ) as file:
        return list(csv.DictReader(file))


def safe_ratio(a, b):
    return round(a / b, 4) if b else None


# 1. Inventory the real Sysmon evidence
sysmon = read_csv("sysmon_process_creation_structured.csv")
powershell = read_csv("powershell_investigation.csv")

# 2. Evaluate the six synthetic pattern-matching cases
tests = read_csv("powershell_controlled_results.csv")

tp = tn = fp = fn = 0

for row in tests:
    truth = int(row["GroundTruth"])
    detected = int(row["Detected"])

    if truth == 1 and detected == 1:
        tp += 1
    elif truth == 0 and detected == 0:
        tn += 1
    elif truth == 0 and detected == 1:
        fp += 1
    else:
        fn += 1

precision = safe_ratio(tp, tp + fp)
recall = safe_ratio(tp, tp + fn)
accuracy = safe_ratio(tp + tn, len(tests))

f1 = (
    round(2 * precision * recall / (precision + recall), 4)
    if precision is not None
    and recall is not None
    and precision + recall > 0
    else None
)

# 3. Inspect the actual Windows Security evidence
replay_path = DATA / "replay" / "security_real_events.jsonl"

with replay_path.open("r", encoding="utf-8-sig") as file:
    real_events = [
        json.loads(line)
        for line in file
        if line.strip()
    ]

failed_logins = [
    e for e in real_events
    if str(e["win"]["system"]["eventID"]) == "4625"
]

group_changes = [
    e for e in real_events
    if str(e["win"]["system"]["eventID"]) == "4732"
]

admin_group_changes = [
    e for e in group_changes
    if e["win"]["eventdata"].get("targetSid")
    == "S-1-5-32-544"
]

# 4. Create the report
report = {
    "project": "SentinelSOC",
    "real_evidence_inventory": {
        "sysmon_process_creation_events": len(sysmon),
        "powershell_process_events": len(powershell),
        "security_replay_events": len(real_events),
        "failed_login_events": len(failed_logins),
        "group_membership_events": len(group_changes),
        "administrators_group_additions": len(admin_group_changes),
    },
    "synthetic_pattern_evaluation": {
        "cases": len(tests),
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "accuracy": accuracy,
    },
    "limitations": [
        "Synthetic pattern metrics are not real-world accuracy.",
        "Real-event inventory does not measure detection accuracy.",
        "Wazuh rule-engine observations are documented separately.",
        "Live Windows agent ingestion is not yet verified."
    ],
}

output = REPORTS / "sentinelsoc_evaluation.json"

with output.open("w", encoding="utf-8") as file:
    json.dump(report, file, indent=2)

print("\n=== SentinelSOC Python Evaluation ===")

for section, values in report.items():
    if isinstance(values, dict):
        print(f"\n{section}")
        for key, value in values.items():
            print(f"  {key}: {value}")

print(f"\nReport saved: {output}")