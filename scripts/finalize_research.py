"""Regenerate the consolidated report, distinguishing live and offline evidence."""
import csv
import json
from pathlib import Path
root = Path(__file__).resolve().parent.parent
reports = root / "reports"
evaluation = json.loads((reports / "sentinelsoc_evaluation.json").read_text(encoding="utf-8-sig"))
with (reports / "live_baseline_vs_custom.csv").open(encoding="utf-8-sig", newline="") as f:
    live = list(csv.DictReader(f))
inv = evaluation["real_evidence_inventory"]
met = evaluation["synthetic_pattern_evaluation"]
lines = ["# SentinelSOC — Consolidated Research Results", "", "## Included evidence inventory", "", "| Evidence | Count |", "| --- | ---: |"]
for key, value in inv.items():
    lines.append(f"| {key.replace('_', ' ')} | {value} |")
lines += ["", "These are counts of the included records, not detection-performance estimates.", "", "## Six-case controlled classification", "", f"Six deliberately constructed PowerShell examples: TP={met['true_positives']}, TN={met['true_negatives']}, FP={met['false_positives']}, FN={met['false_negatives']}. These cannot establish real-world accuracy.", "", "![Synthetic confusion matrix](controlled_confusion_matrix.svg)", "", "## Confirmed live failed-authentication alerts", "", "| Configuration | Rule | Level | Event | Result |", "| --- | --- | ---: | --- | --- |"]
for row in live:
    lines.append(f"| {row['Configuration']} | {row['RuleID']} | {row['Level']} | {row['EventID']} | {row['Outcome']} |")
lines += ["", "The built-in and custom rules were observed on **separate** controlled failed-login attempts. Custom 100101 is a child of 60122 and adds severity/classification, not a measured improvement in accuracy.", "", "[Live validation report](live_detection_results.md) · [Baseline screenshot](../screenshots/09-wazuh-baseline-failed-login.PNG) · [Custom rule evidence](../screenshots/07-wazuh-failed-login-rule-100101.PNG)", "", "## Remaining validation", "", "- Encoded PowerShell: simulated JSON matched rule 100102 in wazuh-logtest; real Sysmon process observed; **live custom alert unverified**.", "- Administrators-group change: existing 4732 records involve Users/IIS_IUSRS; **qualifying live custom alert unverified**.", "- A larger independently labeled dataset, matched baseline comparison, repeated trials, and detection-latency measurements are outstanding.", "", "See [methodology](methodology.md) and [reproducibility](../REPRODUCIBILITY.md).", ""]
output = reports / "consolidated_research_results.md"
output.write_text("\n".join(lines), encoding="utf-8")
print("Consolidated report:", output)
