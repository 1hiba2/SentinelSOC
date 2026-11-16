# SentinelSOC — Live Windows Detection Results

## Experimental environment

- Windows Server 2019 test endpoint (publication alias `LAB-WINDOWS-SERVER`)
- Wazuh agent 4.14.10, ID 002
- Wazuh manager 4.14.10 on Ubuntu Server 24.04
- Windows Security EventChannel and Sysmon telemetry

## Confirmed live authentication results

| Experiment | Windows event | Wazuh rule | Level | Result | Evidence |
| --- | --- | --- | ---: | --- | --- |
| Built-in baseline | 4625 | `60122` | 5 | Detected live | [Baseline alert](../screenshots/09-wazuh-baseline-failed-login.PNG) |
| SentinelSOC custom | 4625 | `100101` | 9 | Detected live | [Custom rule evidence](../screenshots/07-wazuh-failed-login-rule-100101.PNG) |

[Agent connection evidence](../screenshots/08-windows-server-wazuh-agent-connected.PNG) · [Security event replay evidence](../screenshots/10-wazuh-real-event-replay-4625.PNG)

The two alerts were observed on **separate controlled failed-login attempts**. Custom rule `100101` is a child of built-in rule `60122` and increases alert severity/classification; this does **not** prove better sensitivity, accuracy or false-positive performance.

## Additional detection scenarios

**Encoded PowerShell (`100102`):** The endpoint's Sysmon log captured a real encoded PowerShell execution, and a simulated Sysmon-format JSON message matched in `wazuh-logtest`. **A corresponding live custom Wazuh alert was not confirmed.** [Rule-engine evidence](../screenshots/05-wazuh-powershell-custom-rule-100102.PNG).

**Administrators-group addition (`100103`):** The available real Event ID 4732 records refer to `Users` and `IIS_IUSRS`, rather than the local Administrators group. **No qualifying live custom alert was confirmed.** [Offline rule evidence](../screenshots/06-wazuh-privileged-group-rule-100103.PNG).

## Interpretation and limitations

The separate six-case Python pattern test is a deliberately constructed exercise rather than an independently sampled real-world evaluation. No production detection rates, false-positive rates or claims of statistical significance are made.

See [methodology](methodology.md), [validation status](detection_validation_status.csv) and [consolidated findings](consolidated_research_results.md).
