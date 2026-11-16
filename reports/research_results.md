# SentinelSOC — Preliminary Offline Research Results

> **Historical experiment note:** This report documents an earlier isolated JSON replay and the six-case pattern study. Later **live** Windows-to-Wazuh failed-login observations are documented separately in [live_detection_results.md](live_detection_results.md). These evidence types should not be combined into one performance claim.

## Evidence inventory

- Sysmon process creation: **415** events
- Identified PowerShell processes: **19**
- Windows Security JSONL replay: **4** events
- Failed-login events: **1**
- Group-membership events: **3**
- Administrators-group additions: **0**

## Controlled PowerShell pattern examples

Six deliberately constructed examples: TP=3, TN=3, FP=0, FN=0. Precision, recall and F1 within this small set are 1.0. This is not a production accuracy estimate.

## Earlier isolated Wazuh JSON testing

| Scenario | Earlier baseline-only observation | Custom observation |
| --- | --- | --- |
| Failed authentication | Rule `1002` in earlier isolated comparison | Rule `100101`, earlier level 7 configuration |
| Encoded PowerShell | No earlier isolated alert observed | Rule `100102`, level 8 |
| Administrators-group addition | No earlier isolated alert observed | Rule `100103`, level 10 |

These simplified messages were used in preliminary rule-engine testing. A missing isolated alert does **not** establish failure under native live Windows telemetry. The earlier rule levels are historical results, not the final live authentication observation (**rule `100101`, level 9**).

## Historical Security-event replay

- Failed authentication Event ID 4625, record 1312: custom rule `100101`, earlier level 7 replay observation.
- Event ID 4732, records 34, 94 and 95: no qualifying Administrators-group detection.
- Record 34 was not successfully decoded in batch replay and should not count as a validated negative.

**Subsequent live validation:** Built-in `60122` (level 5) and custom `100101` (level 9) were observed on separate genuine failed-login attempts.

See [consolidated results](consolidated_research_results.md) and [methodology](methodology.md).
