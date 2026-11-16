"""Offline evidence inventory and six-case synthetic pattern evaluation."""
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "datasets"
REPORTS = ROOT / "reports"
REPORTS.mkdir(parents=True, exist_ok=True)


def read_csv(name):
    with (DATA / name).open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def ratio(numerator, denominator):
    return round(numerator / denominator, 4) if denominator else None


sysmon = read_csv("sysmon_process_creation_structured.csv")
powershell = read_csv("powershell_investigation.csv")
tests = read_csv("powershell_controlled_results.csv")

tp = tn = fp = fn = 0
for case in tests:
    truth, predicted = int(case["GroundTruth"]), int(case["Detected"])
    if truth == predicted == 1:
        tp += 1
    elif truth == predicted == 0:
        tn += 1
    elif truth == 0:
        fp += 1
    else:
        fn += 1

precision = ratio(tp, tp + fp)
recall = ratio(tp, tp + fn)
f1 = round(2 * precision * recall / (precision + recall), 4) if precision is not None and recall is not None and precision + recall else None

with (DATA / "replay" / "security_real_events.jsonl").open(encoding="utf-8-sig") as stream:
    events = [json.loads(line) for line in stream if line.strip()]

failed = [x for x in events if str(x["win"]["system"]["eventID"]) == "4625"]
changes = [x for x in events if str(x["win"]["system"]["eventID"]) == "4732"]
admin = [x for x in changes if x["win"]["eventdata"].get("targetSid") == "S-1-5-32-544"]

result = {
    "project": "SentinelSOC",
    "real_evidence_inventory": {
        "sysmon_process_creation_events": len(sysmon),
        "powershell_process_events": len(powershell),
        "security_replay_events": len(events),
        "failed_login_events": len(failed),
        "group_membership_events": len(changes),
        "administrators_group_additions": len(admin),
    },
    "synthetic_pattern_evaluation": {
        "cases": len(tests), "true_positives": tp, "true_negatives": tn,
        "false_positives": fp, "false_negatives": fn,
        "precision": precision, "recall": recall, "f1_score": f1,
        "accuracy": ratio(tp + tn, len(tests)),
    },
    "limitations": [
        "Synthetic pattern metrics are not real-world accuracy.",
        "Real-event inventory does not measure detection accuracy.",
        "Wazuh rule-engine observations are documented separately.",
        "Live failed-authentication ingestion was verified separately; live PowerShell and Administrators-group custom alerts remain unverified.",
    ],
}
output = REPORTS / "sentinelsoc_evaluation.json"
output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print("SentinelSOC offline evaluation:")
print(json.dumps(result, indent=2))
print("Report saved:", output)
