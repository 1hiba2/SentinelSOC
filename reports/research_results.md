# SentinelSOC â€” Preliminary Research Results

## Real evidence inventory

- Sysmon process-creation events: 415
- Identified PowerShell events: 19
- Windows Security replay events: 4
- Failed-login events: 1
- Group membership events: 3
- Administrators-group additions: 0

## Controlled pattern evaluation

- Cases: 6
- TP: 3; TN: 3; FP: 0; FN: 0
- Precision: 1.0
- Recall: 1.0
- F1-score: 1.0

These six examples were deliberately constructed to test
the selected regular-expression indicators. Results are
not independent estimates of real-world detection accuracy.

## Isolated Wazuh JSON replay comparison

| Scenario | Built-in-only outcome | With SentinelSOC |
|---|---|---|
| Failed authentication (4625) | 1002 | 100101 |
| Encoded PowerShell | No Phase 3 alert | 100102 |
| Administrators group addition | No Phase 3 alert | 100103 |

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
