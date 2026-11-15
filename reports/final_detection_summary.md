# SentinelSOC - Detection Validation Summary

## Detection results

| Scenario | Rule | Validation status |
|---|---|---|
| Failed authentication | 100101 | Verified |
| Suspicious PowerShell | 100102 | Rule-engine verified; live alert not observed |
| Administrators group addition | 100103 | Offline validation; live alert not verified |

## Experimental interpretation

- Failed authentication was validated through live Windows-to-Wazuh ingestion.
- The PowerShell rule matched a controlled simulated Sysmon JSON event.
- A genuine encoded PowerShell process was observed in the Windows Sysmon log.
- No corresponding live Wazuh PowerShell alert was observed.
- Existing real group-membership events concern Users and IIS_IUSRS, not Administrators.
- A live Administrators-group addition alert was not verified.

## Research limitations

- The six-case synthetic pattern evaluation is not a real-world accuracy benchmark.
- Baseline and custom authentication alerts were observed on separate login attempts.
- The custom authentication rule provides additional classification and severity.
- No production detection-rate or false-positive-rate claims are made.
