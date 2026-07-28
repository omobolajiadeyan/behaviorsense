# External Evaluator Guide

This guide is for an external professional who wants to understand
BehaviorSense quickly, run it safely, and judge whether the tool is useful for
behavioral security triage.

## Product Promise

BehaviorSense analyzes local security logs, profiles users or IP-backed
entities, and ranks anomalous behavior with explainable signals. It is meant to
support triage, not produce a final insider-threat verdict.

## Five-Minute Demo

Run the bundled sample dataset:

```bash
python3 detector.py sample_data/ --verbose
```

Export JSON:

```bash
python3 detector.py sample_data/ --output report.json
```

Important: the sample dataset intentionally contains one `CRITICAL` entity.
The CLI exits with code `2` when a critical finding is present. That means the
detector worked; it is not a crash.

## Expected Outcome

The sample report should show:

| Field | Expected Result |
|---|---|
| Events analyzed | `23` |
| Entities profiled | `5` |
| Critical entities | `1` |
| Top entity | `mallory` |
| Top risk | `CRITICAL` |
| Risk score | `100.0%` |

The top entity should include signals such as high failure rate, many source
IPs, broad endpoint access, large data volume, high event volume, and off-hours
activity.

## Who This Is For

- SOC analysts reviewing suspicious authentication or access patterns
- security engineers prototyping UEBA-style logic
- educators demonstrating behavioral anomaly concepts
- teams that need local, dependency-free security triage examples

## What This Is Not

BehaviorSense does not replace:

- a commercial SIEM or UEBA platform
- identity-provider risk scoring
- endpoint detection and response
- human investigation of user intent
- environment-specific baselines and asset context

Use the score as prioritization evidence, then validate the activity with real
identity, endpoint, network, and business context.

## What To Review

- parser support for SSH auth logs, web logs, CSV, JSON, and NDJSON
- z-score deviation logic
- deterministic security-signal boosts
- MITRE ATT&CK-style technique hints
- JSON export for downstream review
- tests for parser, scoring, and CLI behavior
