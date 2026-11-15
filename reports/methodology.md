# SentinelSOC - Research Methodology

## Objective

Evaluate custom security detection rules for Windows
authentication failures, suspicious PowerShell execution,
and local Administrators-group membership changes.

## Laboratory

- Windows 10 host with Oracle VirtualBox
- Windows Server 2019 endpoint
- Ubuntu Server 24.04 running Wazuh Manager 4.14.10
- Wazuh Windows agent and Sysmon event collection
- Python-based evidence analysis and reporting

## Detection scenarios

### 1. Failed authentication

Windows Security Event ID 4625 was collected through
the Windows Wazuh agent.

A built-in Wazuh alert, rule 60122 at level 5,
was observed during a controlled failed-login test.

A subsequent controlled test generated custom rule
100101 at level 9.

These observations establish successful ingestion
and custom classification, not improved accuracy.

### 2. Suspicious PowerShell

A controlled encoded PowerShell command generated
a real Sysmon process-creation event.

Custom rule 100102, level 8, matched a simulated
Sysmon-format JSON event in wazuh-logtest.

No corresponding live Wazuh alert was observed.
The two results are documented separately.

### 3. Privileged group membership

Existing Windows Security Event ID 4732 records
were examined.

They concerned Users and IIS_IUSRS groups rather
than an addition to the local Administrators group.

A qualifying live custom rule 100103 alert has
not been verified.

## Evaluation methodology

Six deliberately constructed PowerShell pattern
examples were evaluated using Python.

Results:
- True positives: 3
- True negatives: 3
- False positives: 0
- False negatives: 0

These figures apply only to the controlled examples.
They are not estimates of real-world detection accuracy.

## Limitations

- Small, intentionally constructed evaluation set
- Separate authentication attempts for baseline and custom alerts
- No independently labeled production dataset
- No statistically meaningful sensitivity or false-positive comparison
- Resource-constrained virtualization environment
- Live forwarding not demonstrated for all three scenarios

## Reproducibility

Detection rules, scripts, datasets, reports,
and selected screenshots are stored within the
SentinelSOC project.

Experiments should be repeated only in an
authorized, isolated laboratory.
