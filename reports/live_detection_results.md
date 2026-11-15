# SentinelSOC — Live Windows Detection Results

## Experimental environment

- Endpoint: Windows Server 2019, LAB-WINDOWS-SERVER
- Endpoint agent: Wazuh agent 002
- SIEM manager: Wazuh 4.14.10 on Ubuntu Server
- Telemetry: Windows Security EventChannel and Sysmon

## Verified results

### Baseline experiment

- Windows event: 4625 (failed authentication)
- Wazuh rule: 60122
- Alert level: 5
- Result: Detected during live ingestion
- Evidence: screenshots/09-live-windows-failed-login-alert.png

### Custom detection experiment

- Windows event: 4625 (failed authentication)
- Wazuh rule: 100101
- Alert level: 9
- Result: Detected during live ingestion
- Evidence: screenshots/10-custom-windows-failed-login-rule.png

## Interpretation

The custom rule uses the built-in rule 60122 as its parent.
It provides custom classification and higher alert severity.

The two alerts were observed on separate controlled login attempts.
This experiment does not demonstrate better accuracy or fewer
false positives than the baseline.

## Evaluation limitations

The six synthetic pattern-matching cases are not an independent
real-world evaluation dataset.

Live detection for the PowerShell and Administrators-group scenarios
requires separate validation.

No production detection-rate, false-positive-rate, or statistical
significance claims are made.
