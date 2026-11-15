# SentinelSOC

Security detection engineering and research project using
Wazuh, Sysmon, Windows Server 2019, and Python.

## Overview

SentinelSOC investigates three Windows detection scenarios:

1. Failed authentication
2. Suspicious PowerShell execution
3. Local Administrators-group membership changes

The project combines real Windows telemetry, Wazuh rule
development, controlled experiments, and Python analysis.

## Laboratory

- Windows 10 host
- Oracle VirtualBox
- Ubuntu Server 24.04
- Wazuh Manager 4.14.10
- Windows Server 2019
- Wazuh Windows agent 4.14.10
- Sysmon 15.22
- Python

## Validated results

| Scenario | Custom rule | Result |
|---|---|---|
| Failed authentication | 100101 | Verified live |
| Suspicious PowerShell | 100102 | Rule-engine verified; live alert not observed |
| Administrators-group addition | 100103 | Live alert not verified |

Built-in Wazuh rule 60122 and custom rule 100101 were
observed on separate controlled failed-login attempts.

Custom rule 100102 successfully matched a simulated
Sysmon JSON event. A real encoded PowerShell execution
was captured by Sysmon, but no corresponding live custom
Wazuh alert was observed.

Existing real Event ID 4732 records concerned Users and
IIS_IUSRS rather than local Administrators membership.

## Python evaluation

Six controlled PowerShell pattern examples produced:

- 3 true positives
- 3 true negatives
- 0 false positives
- 0 false negatives

These results describe deliberately constructed test
cases, not production detection performance.

## Repository contents

- configurations/ : Saved detection rules
- scripts/ : Python analysis and reporting scripts
- datasets/ : Controlled test and exported evidence
- reports/ : Results, methodology, and MITRE mappings
- screenshots/ : Selected experimental evidence

## Research interpretation

This project demonstrates a functioning Windows-to-Wazuh
pipeline and live custom failed-authentication detection.

The PowerShell and Administrators-group experiments have
documented limitations. No production accuracy claims
are made.

## Documentation

- reports/methodology.md
- reports/final_detection_summary.md
- reports/consolidated_research_results.md
- reports/mitre_attack_mapping.csv
- reports/detection_validation_status.csv

## Ethical scope

All experiments were conducted in an isolated,
authorized laboratory. No third-party systems were
targeted.
