# BehaviorSense

BehaviorSense is a local behavioral anomaly detector for security logs. It profiles users and IP-backed entities, compares behavior against the population baseline, and adds explicit security-signal boosts for patterns such as high authentication failure rate, many source IPs, broad endpoint access, large transfer volume, and off-hours activity.

It is designed for explainable triage, not black-box verdicts. The output shows the risk score, contributing signals, MITRE ATT&CK-style technique hints, and recommended analyst actions.

## Why This Exists

Traditional rule-based tools catch known patterns. BehaviorSense focuses on suspicious behavior that stands out from the baseline:

- A user with many failed logins from many IPs
- Off-hours access paired with broad endpoint activity
- Unusual data transfer volume
- Entity behavior that is statistically different from peers

BehaviorSense runs locally and uses only the Python standard library. No log data is sent to external services.

## Features

- Profiles users and IPs across behavioral dimensions
- Z-score deviation analysis against the observed population
- Security-signal boosts for analyst-relevant patterns
- MITRE ATT&CK-style technique hints for triage context
- Recommended next actions for suspicious entities
- Supports SSH auth logs, web access logs, CSV, JSON, and NDJSON
- JSON export for SIEM/SOAR handoff or reporting
- Zero runtime dependencies
- Unit-tested parser, scoring, and CLI behavior

## Detection Model

BehaviorSense combines two layers:

1. **Population deviation:** z-scores compare each entity against the dataset baseline.
2. **Security signals:** deterministic boosts capture known suspicious combinations that z-scores can understate on small datasets.

Current security signals:

| Signal | Trigger |
|---|---|
| `high_failure_rate` | At least 50% failed events and at least 3 failures |
| `many_source_ips` | 5 or more unique source IPs |
| `broad_endpoint_access` | 5 or more unique endpoints |
| `large_data_volume` | 5 MB or more transferred |
| `high_event_volume` | 10 or more events |
| `off_hours_activity` | Average activity before 06:00 or after 22:00 |

This is a triage engine. It can produce false positives and false negatives, especially on small or synthetic datasets.

## Installation

```bash
git clone https://github.com/omobolajiadeyan/behaviorsense.git
cd behaviorsense
python --version  # Python 3.10+ required
```

Optional local install:

```bash
python -m pip install .
behaviorsense sample_data/ --verbose
```

## Usage

```bash
# Analyze sample data
python detector.py sample_data/

# Show full z-score, signal, technique, and action context
python detector.py sample_data/ --verbose

# Show top 10 riskiest entities
python detector.py sample_data/ --top 10

# Only show HIGH and CRITICAL entities
python detector.py sample_data/ --threshold HIGH

# Export to JSON
python detector.py sample_data/ --output report.json

# Analyze real logs
python detector.py /var/log/auth.log
python detector.py /var/log/nginx/
```

Exit codes:

- `0`: completed without critical findings
- `1`: invalid input or runtime error
- `2`: at least one `CRITICAL` entity found

## Example Output

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

Security signals:
  - high failure rate: 7 failed events across 12 total events
  - many source ips: 8 unique source IPs
  - broad endpoint access: 5 unique endpoints
  - large data volume: 8,324,480 bytes transferred
  - high event volume: 12 events
  - off hours activity: average activity hour 2.0

Technique hints:
  - T1110 Brute Force
  - T1078 Valid Accounts
  - T1083 File and Directory Discovery
  - T1041 Exfiltration Over C2 Channel
```

## JSON Export

```bash
python detector.py sample_data/ --output report.json
```

The exported report includes:

- `total_events`
- `total_entities`
- ranked `results`
- per-entity `z_scores`
- security `signals`
- `technique_hints`
- `recommended_actions`

## Architecture

```text
behaviorsense/
├── detector.py          # CLI entrypoint and report renderer
├── parser.py            # Log parsers and event normalization
├── profiler.py          # Per-entity behavioral profiling
├── scorer.py            # Z-score, security-signal, and risk ranking logic
├── sample_data/
│   └── activity.csv     # Synthetic sample data with an anomalous entity
├── tests/               # Unit tests for parser, scoring, and CLI behavior
└── .github/workflows/   # CI test workflow
```

## Verification

```bash
python -m unittest discover -s tests -v
python detector.py sample_data/ --verbose
```

## Roadmap

- [ ] Time-windowed baselines to detect slow-and-low attacks
- [ ] Peer-group comparisons by department, role, or service account type
- [ ] Sigma or detection-rule export for downstream security tooling
- [ ] Richer MITRE ATT&CK mappings with confidence levels
- [ ] Optional dashboard or HTML report generated from JSON output
- [ ] Optional Isolation Forest mode behind an explicit extra dependency

## Author

**Omobolaji Adeyan** - Cybersecurity Engineer  
GitHub: https://github.com/omobolajiadeyan

## License

MIT License. See [LICENSE](LICENSE).
