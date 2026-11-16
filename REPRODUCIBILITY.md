# Reproducing SentinelSOC's offline research

This repository provides the datasets and Python scripts needed to recreate **offline evidence counts and research reports**. It does **not** supply the original Windows virtual machine, Wazuh manager or a procedure for replaying the live endpoint experiment.

## Requirements

- Python 3.10 or later
- Standard Python library only (no package installation needed)
- The included `datasets/` and `reports/` folders

## Steps

1. Download the repository from GitHub using **Code → Download ZIP**, then extract it.
2. Open a terminal in the extracted `SentinelSOC` repository folder. PowerShell is **not required**.
3. Run the following commands **in order**:

```text
python scripts/evaluate.py
python scripts/build_research_report.py
python scripts/finalize_research.py
```

If your system names Python `python3`, substitute that command.

## Files generated

| Script | Output files |
| --- | --- |
| `evaluate.py` | `reports/sentinelsoc_evaluation.json` |
| `build_research_report.py` | `reports/baseline_vs_custom.csv`, `reports/controlled_confusion_matrix.svg`, `reports/research_results.md` |
| `finalize_research.py` | `reports/consolidated_research_results.md` |

**Caution:** These commands overwrite the listed generated reports. The source scripts resolve file paths relative to their own location, so the repo can be extracted anywhere.

## Expected counts for the included evidence

- 415 Sysmon process-creation events
- 19 identified PowerShell process events
- Four Windows Security replay records: one failed authentication and three group membership changes
- Zero Administrators-group additions in the included replay
- Six deliberately constructed PowerShell examples: TP=3, TN=3, FP=0, FN=0

These numbers describe specific included records and controlled examples; they **do not** measure operational detection accuracy.

## Evidence boundaries

The live failed-login observations are documented in [live_detection_results.md](reports/live_detection_results.md). The PowerShell rule-engine observation used simulated input and is not equivalent to a live custom Wazuh alert. No qualifying live Administrators-group addition was verified.

See [research methodology](reports/methodology.md) and [validation status](reports/detection_validation_status.csv).
