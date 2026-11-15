import csv
import json
from pathlib import Path

root = Path(__file__).resolve().parent.parent
reports = root / "reports"

with (reports / "sentinelsoc_evaluation.json").open(
    encoding="utf-8-sig"
) as file:
    evaluation = json.load(file)

with (reports / "live_baseline_vs_custom.csv").open(
    encoding="utf-8-sig", newline=""
) as file:
    live = list(csv.DictReader(file))

synthetic = evaluation["synthetic_pattern_evaluation"]
inventory = evaluation["real_evidence_inventory"]

lines = [
    "# SentinelSOC — Consolidated Research Results",
    "",
    "## 1. Real Windows evidence inventory",
    "",
]

for name, value in inventory.items():
    lines.append(f"- {name}: {value}")

lines += [
    "",
    "These counts describe the previously collected evidence.",
    "They are not measurements of detection accuracy.",
    "",
    "## 2. Controlled synthetic evaluation",
    "",
    f"- Test cases: {synthetic['cases']}",
    f"- True positives: {synthetic['true_positives']}",
    f"- True negatives: {synthetic['true_negatives']}",
    f"- False positives: {synthetic['false_positives']}",
    f"- False negatives: {synthetic['false_negatives']}",
    f"- Precision: {synthetic['precision']:.2f}",
    f"- Recall: {synthetic['recall']:.2f}",
    f"- F1 score: {synthetic['f1_score']:.2f}",
    "",
    "These six deliberately constructed cases do not establish",
    "real-world detection accuracy.",
    "",
    "## 3. Verified live detection",
    "",
    "| Configuration | Rule | Level | Event | Result |",
    "|---|---|---|---|---|",
]

for row in live:
    lines.append(
        f"| {row['Configuration']} | {row['RuleID']} | "
        f"{row['Level']} | {row['EventID']} | "
        f"{row['Outcome']} |"
    )

lines += [
    "",
    "The live tests used Windows Server 2019, agent 002.",
    "The baseline and custom results came from separate",
    "controlled authentication events.",
    "",
    "Custom rule 100101 is a child of built-in rule 60122.",
    "The custom rule increases alert severity and classification;",
    "it is not evidence of improved detection sensitivity.",
    "",
    "## 4. Limitations and remaining validation",
    "",
    "- The live failed-login scenario is verified.",
    "- Live PowerShell custom detection remains unverified.",
    "- Live Administrators-group detection remains unverified.",
    "- Independent detection-rate evaluation is outstanding.",
    "- Earlier isolated JSON replay results are not equivalent",
    "  to results from native live EventChannel ingestion.",
    "",
    "## 5. Evidence",
    "",
    "- screenshots/08-windows-server-wazuh-agent-connected.png",
    "- screenshots/09-live-windows-failed-login-alert.png",
    "- screenshots/10-custom-windows-failed-login-rule.png",
    "- reports/live_detection_results.md",
    "",
]

output = reports / "consolidated_research_results.md"
output.write_text("\n".join(lines) + "\n", encoding="utf-8")

print("Consolidated report created:")
print(output)
print("Synthetic cases:", synthetic["cases"])
print("Live detection records:", len(live))
