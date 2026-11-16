"""Regenerate controlled-test outputs without overwriting live-validation reports."""
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"
REPORTS.mkdir(exist_ok=True)
evaluation = json.loads((REPORTS / "sentinelsoc_evaluation.json").read_text(encoding="utf-8-sig"))
m = evaluation["synthetic_pattern_evaluation"]
i = evaluation["real_evidence_inventory"]

# These are historical *isolated replay* observations, not the final live results.
rows = [
    {"Scenario":"Failed authentication (4625)", "BaselineRule":"1002", "BaselineLevel":"2", "CustomRule":"100101", "CustomLevel":"7"},
    {"Scenario":"Encoded PowerShell", "BaselineRule":"No earlier isolated alert", "BaselineLevel":"", "CustomRule":"100102", "CustomLevel":"8"},
    {"Scenario":"Administrators group addition", "BaselineRule":"No earlier isolated alert", "BaselineLevel":"", "CustomRule":"100103", "CustomLevel":"10"},
]
with (REPORTS / "baseline_vs_custom.csv").open("w", encoding="utf-8", newline="") as stream:
    writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)

cells = [("TN", m["true_negatives"], 30, 85), ("FP", m["false_positives"], 190, 85), ("FN", m["false_negatives"], 30, 245), ("TP", m["true_positives"], 190, 245)]
svg = ['<svg xmlns="http://www.w3.org/2000/svg" width="400" height="420" viewBox="0 0 400 420">', '<rect width="400" height="420" fill="white"/>', '<text x="200" y="35" text-anchor="middle" font-size="21" fill="#172554">Controlled Test Confusion Matrix</text>', '<text x="200" y="65" text-anchor="middle" font-size="13">Predicted negative / positive</text>']
for label, count, x, y in cells:
    svg += [f'<rect x="{x}" y="{y}" width="150" height="145" rx="8" fill="#dbeafe" stroke="#1d4ed8"/>', f'<text x="{x+75}" y="{y+56}" text-anchor="middle" font-size="19">{label}</text>', f'<text x="{x+75}" y="{y+105}" text-anchor="middle" font-size="36" font-weight="bold">{count}</text>']
svg += ['<text x="200" y="405" font-size="12" text-anchor="middle">Synthetic pattern-matching tests only (n=6)</text>', '</svg>']
(REPORTS / "controlled_confusion_matrix.svg").write_text("\n".join(svg) + "\n", encoding="utf-8")

report = f"""# SentinelSOC — Preliminary Offline Research Results

> This report documents earlier isolated JSON replay results and controlled pattern tests. Later **live** failed-login results are documented separately in [live_detection_results.md](live_detection_results.md).

## Included evidence inventory

- Sysmon process-creation events: {i['sysmon_process_creation_events']}
- Identified PowerShell events: {i['powershell_process_events']}
- Windows Security replay events: {i['security_replay_events']}
- Failed-login replay events: {i['failed_login_events']}
- Group-membership replay events: {i['group_membership_events']}
- Administrators-group additions in replay: {i['administrators_group_additions']}

## Six deliberately constructed PowerShell test cases

- Cases: {m['cases']}; TP: {m['true_positives']}; TN: {m['true_negatives']}; FP: {m['false_positives']}; FN: {m['false_negatives']}
- Precision: {m['precision']}; recall: {m['recall']}; F1: {m['f1_score']}

These results are not estimates of real-world detection accuracy.

## Historical isolated Wazuh rule testing

| Scenario | Earlier baseline observation | Earlier custom observation |
| --- | --- | --- |
| Failed authentication | Rule 1002 | Custom 100101 (earlier level 7 test) |
| Encoded PowerShell | No earlier isolated alert observed | Custom 100102 (level 8) |
| Administrators-group addition | No earlier isolated alert observed | Custom 100103 (level 10) |

These tests used simplified synthetic messages. The earlier level 7 observation is **not** the later live level 9 result. A missing isolated alert does not demonstrate failure under native Windows telemetry.

## Earlier real-event replay and subsequent live validation

Event 4625 record 1312 was replayed in the earlier rule test. Event 4732 records 34, 94 and 95 were not qualifying Administrators-group additions; record 34 failed batch decoding and must not count as a validated negative.

**Later live verification:** Built-in rule 60122 (level 5) and custom 100101 (level 9) were observed on **separate** controlled failed-login attempts.

See [consolidated results](consolidated_research_results.md).
"""
(REPORTS / "research_results.md").write_text(report, encoding="utf-8")
print("Regenerated baseline_vs_custom.csv, controlled_confusion_matrix.svg and research_results.md")
