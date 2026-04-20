# BehaviorSense

An AI-powered behavioral anomaly detection engine that profiles every user and IP address from log data, then uses statistical deviation analysis (z-score based) to surface the most suspicious entities — ranked by risk score.

Built because traditional rule-based security tools only catch known attack patterns. BehaviorSense catches the *unknown* — unusual behavior that doesn't match any signature but deviates significantly from what's normal for that user or the wider population.

## How It Works

**Phase 1 — Profiling**  
Every user and IP address is profiled across 6 behavioral dimensions:
- `failure_rate` — ratio of failed to total events
- `ip_diversity` — number of unique IP addresses used
- `endpoint_diversity` — number of unique endpoints accessed
- `avg_hour` — typical hour of activity
- `total_bytes` — volume of data transferred
- `event_count` — overall activity level

**Phase 2 — Population Baseline**  
The engine computes a mean and standard deviation for each metric across all entities in the dataset. This is the "normal" for your environment.

**Phase 3 — Anomaly Scoring**  
Each entity is scored by how many standard deviations (z-score) they deviate from the baseline in each dimension. Deviations are weighted by security relevance and combined into a single 0–100% risk score using sigmoid normalisation.

**Phase 4 — Risk Ranking**  
Entities are ranked from most to least anomalous with a full breakdown of which metrics drove the score.

## Features

- Profiles users and IPs across 6 behavioral dimensions
- Z-score deviation analysis against population baseline
- Weighted risk scoring (failure rate weighted most heavily)
- Supports SSH auth logs, web access logs, CSV, and JSON formats
- Auto-detects log format
- Shows top offending entities with per-metric breakdowns
- JSON export for SIEM/SOAR integration
- Zero dependencies — pure Python standard library

## Installation

```bash
git clone https://github.com/oadeyan/behaviorsense.git
cd behaviorsense
python --version  # Python 3.10+ required
```

## Usage

```bash
# Analyze sample data
python detector.py sample_data/

# Show top 10 riskiest entities
python detector.py sample_data/ --top 10

# Show full z-score breakdown per entity
python detector.py sample_data/ --verbose

# Only show HIGH and CRITICAL entities
python detector.py sample_data/ --threshold HIGH

# Export to JSON
python detector.py sample_data/ --output report.json

# Analyze real system logs (Linux)
python detector.py /var/log/auth.log
python detector.py /var/log/nginx/
```

## Example Output

```
  BEHAVIORSENSE
  AI behavioral anomaly detection

Loading 1 log file(s)...
Profiling 23 events...

══════════════════════════════════════════════════════════════
  BEHAVIORSENSE REPORT
══════════════════════════════════════════════════════════════
  Events analyzed   : 23
  Entities profiled : 5
  CRITICAL          : 1
  HIGH              : 0
  MEDIUM            : 0
  NORMAL            : 4
══════════════════════════════════════════════════════════════

TOP 5 ENTITIES BY RISK SCORE

  ──────────────────────────────────────────────────────────
  #1  mallory  [CRITICAL]
  Risk Score  : ████████████████████  91.3%
  Events      : 11  |  Failed logins: 7
  Unique IPs  : 8   |  Endpoints: 5
  Data moved  : 8,398,848 bytes
  Top anomaly : Failure Rate

  Z-score breakdown:
    failure_rate        :  3.84  ████████   <<
    ip_diversity        :  3.21  ███████    <<
    total_bytes         :  2.91  █████████  <<
    endpoint_diversity  :  1.44  █
    avg_hour            :  1.12  █
```

## Architecture

```
behaviorsense/
├── detector.py          # CLI entrypoint + report renderer
├── profiler.py          # Per-entity behavioral profiling
├── scorer.py            # Z-score anomaly scoring + risk ranking
├── parser.py            # Log parsers (auth, access, CSV, JSON)
├── sample_data/
│   └── activity.csv     # Sample user activity log with anomalies
└── README.md
```

## Roadmap

- [ ] Isolation Forest integration (scikit-learn) for non-linear anomaly detection
- [ ] Time-series windowing to detect slow-and-low attacks
- [ ] Peer-group analysis (compare against users in the same role/department)
- [ ] MITRE ATT&CK technique suggestion based on anomaly type
- [ ] Dashboard visualization with matplotlib

## Author

**Omobolaji Adeyan** — Cybersecurity Portfolio Project  
[GitHub](https://github.com/oadeyan)
