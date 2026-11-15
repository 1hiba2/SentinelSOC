import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"
REPORTS.mkdir(exist_ok=True)

with (REPORTS / "sentinelsoc_evaluation.json").open(
    encoding="utf-8"
) as f:
    evaluation = json.load(f)

metrics = evaluation["synthetic_pattern_evaluation"]
inventory = evaluation["real_evidence_inventory"]

# Recorded outcomes of the isolated synthetic JSON tests.
comparison = [
    {
        "Scenario": "Failed authentication (4625)",
        "BaselineRule": "1002",
        "BaselineLevel": "2",
        "CustomRule": "100101",
        "CustomLevel": "7",
    },
    {
        "Scenario": "Encoded PowerShell",
        "BaselineRule": "No Phase 3 alert",
        "BaselineLevel": "",
        "CustomRule": "100102",
        "CustomLevel": "8",
    },
    {
        "Scenario": "Administrators group addition",
        "BaselineRule": "No Phase 3 alert",
        "BaselineLevel": "",
        "CustomRule": "100103",
        "CustomLevel": "10",
    },
]

csv_path = REPORTS / "baseline_vs_custom.csv"

with csv_path.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(
        f, fieldnames=list(comparison[0].keys())
    )
    writer.writeheader()
    writer.writerows(comparison)

# Confusion matrix for six constructed test cases.
tn = metrics["true_negatives"]
fp = metrics["false_positives"]
fn = metrics["false_negatives"]
tp = metrics["true_positives"]

matrix = [
    ("TN", tn, 30, 85),
    ("FP", fp, 190, 85),
    ("FN", fn, 30, 245),
    ("TP", tp, 190, 245),
]

parts = [
    '<svg xmlns="http://www.w3.org/2000/svg" '
    'width="400" height="420" viewBox="0 0 400 420">',
    '<rect width="400" height="420" fill="white"/>',
    '<text x="200" y="35" font-size="21" '
    'text-anchor="middle" fill="#172554">'
    'Controlled Test Confusion Matrix</text>',
    '<text x="200" y="65" font-size="13" '
    'text-anchor="middle">Predicted negative / positive</text>',
]

for label, count, x, y in matrix:
    parts.extend([
        f'<rect x="{x}" y="{y}" width="150" height="145" '
        'rx="8" fill="#dbeafe" stroke="#1d4ed8"/>',
        f'<text x="{x+75}" y="{y+56}" font-size="19" '
        f'text-anchor="middle">{label}</text>',
        f'<text x="{x+75}" y="{y+105}" font-size="36" '
        f'text-anchor="middle" font-weight="bold">{count}</text>',
    ])

parts.extend([
    '<text x="200" y="405" font-size="12" '
    'text-anchor="middle">Synthetic pattern-matching tests only (n=6)</text>',
    '</svg>',
])

svg_path = REPORTS / "controlled_confusion_matrix.svg"
svg_path.write_text("\n".join(parts), encoding="utf-8")

rows = "\n".join(
    f"| {c['Scenario']} | {c['BaselineRule']} | "
    f"{c['CustomRule']} |"
    for c in comparison
)

markdown = f"""# SentinelSOC â€” Preliminary Research Results

## Real evidence inventory

- Sysmon process-creation events: {inventory['sysmon_process_creation_events']}
- Identified PowerShell events: {inventory['powershell_process_events']}
- Windows Security replay events: {inventory['security_replay_events']}
- Failed-login events: {inventory['failed_login_events']}
- Group membership events: {inventory['group_membership_events']}
- Administrators-group additions: {inventory['administrators_group_additions']}

## Controlled pattern evaluation

- Cases: {metrics['cases']}
- TP: {tp}; TN: {tn}; FP: {fp}; FN: {fn}
- Precision: {metrics['precision']}
- Recall: {metrics['recall']}
- F1-score: {metrics['f1_score']}

These six examples were deliberately constructed to test
the selected regular-expression indicators. Results are
not independent estimates of real-world detection accuracy.

## Isolated Wazuh JSON replay comparison

| Scenario | Built-in-only outcome | With SentinelSOC |
|---|---|---|
{rows}

The comparison uses simplified synthetic JSON messages.
Built-in Windows and Sysmon rules can require native event
metadata, parent-rule matches, and different fields.
A missing Phase 3 alert in this experiment does not
demonstrate failure on real Windows telemetry.

## Real Windows Security replay

- Record 1312 (4625): custom rule 100101, level 7.
- Records 34, 94, 95 (4732): no custom 100103 alert observed.
- Record 34 did not decode successfully during batch replay,
  so it is not counted as a validated negative detection.
- The replay was derived from EVTX evidence, not received live.

## Outstanding validation

- Live Windows Server 2019 agent enrollment and ingestion.
- Native-format event testing and baseline comparison.
- Additional independently labeled positives and negatives.
- Realistic detection-rate and false-positive evaluation.
"""

report_path = REPORTS / "research_results.md"
report_path.write_text(markdown, encoding="utf-8")

print("=== SentinelSOC Research Outputs ===")
for path in (csv_path, svg_path, report_path):
    print(f"Created: {path.name} ({path.stat().st_size} bytes)")