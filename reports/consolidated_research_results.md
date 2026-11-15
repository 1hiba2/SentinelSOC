# SentinelSOC — Consolidated Research Results

## 1. Real Windows evidence inventory

- sysmon_process_creation_events: 415
- powershell_process_events: 19
- security_replay_events: 4
- failed_login_events: 1
- group_membership_events: 3
- administrators_group_additions: 0

These counts describe the previously collected evidence.
They are not measurements of detection accuracy.

## 2. Controlled synthetic evaluation

- Test cases: 6
- True positives: 3
- True negatives: 3
- False positives: 0
- False negatives: 0
- Precision: 1.00
- Recall: 1.00
- F1 score: 1.00

These six deliberately constructed cases do not establish
real-world detection accuracy.

## 3. Verified live detection

| Configuration | Rule | Level | Event | Result |
|---|---|---|---|---|
| Built-in baseline | 60122 | 5 | 4625 | Detected live |
| SentinelSOC custom | 100101 | 9 | 4625 | Detected live |

The live tests used Windows Server 2019, agent 002.
The baseline and custom results came from separate
controlled authentication events.

Custom rule 100101 is a child of built-in rule 60122.
The custom rule increases alert severity and classification;
it is not evidence of improved detection sensitivity.

## 4. Limitations and remaining validation

- The live failed-login scenario is verified.
- Live PowerShell custom detection remains unverified.
- Live Administrators-group detection remains unverified.
- Independent detection-rate evaluation is outstanding.
- Earlier isolated JSON replay results are not equivalent
  to results from native live EventChannel ingestion.

## 5. Evidence

- screenshots/08-windows-server-wazuh-agent-connected.png
- screenshots/09-live-windows-failed-login-alert.png
- screenshots/10-custom-windows-failed-login-rule.png
- reports/live_detection_results.md

