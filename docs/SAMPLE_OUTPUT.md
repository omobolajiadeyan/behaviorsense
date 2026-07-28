# Sample Output

Command:

```bash
python3 detector.py sample_data/ --verbose
```

Expected high-level result:

```text
BEHAVIORSENSE REPORT
==============================================================
  Events analyzed   : 23
  Entities profiled : 5
  CRITICAL          : 1
  HIGH              : 0
  MEDIUM            : 0
  NORMAL            : 4

TOP 1 ENTITIES BY RISK SCORE

#1  mallory  [CRITICAL]
Risk Score  : 100.0%
Events      : 12  |  Failed logins: 7
Unique IPs  : 8   |  Endpoints: 5
Data moved  : 8,324,480 bytes
Top anomaly : Failure Rate
```

Expected signals:

- high failure rate
- many source IPs
- broad endpoint access
- large data volume
- high event volume
- off-hours activity

Expected technique hints include:

- `T1110 Brute Force`
- `T1078 Valid Accounts`
- `T1083 File and Directory Discovery`
- `T1041 Exfiltration Over C2 Channel`

JSON export:

```bash
python3 detector.py sample_data/ --output report.json
```

The JSON report includes:

- `total_events`
- `total_entities`
- ranked `results`
- per-entity `z_scores`
- security `signals`
- `technique_hints`
- `recommended_actions`

Exit code note: the sample contains a critical finding, so the command exits
with code `2` after producing the report.
