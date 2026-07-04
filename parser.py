"""
Log parsers for common formats: SSH auth logs, web access logs, CSV activity logs.
Each parser returns a normalized list of event dicts.
"""

import re
import csv
import json
from pathlib import Path


def _to_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def normalize_event(event: dict) -> dict:
    """Return a normalized event dict used consistently by the profiler."""
    status = str(event.get("status", "")).lower()
    status_code = str(event.get("status_code", ""))
    if status_code in ("401", "403") and status not in ("failed", "failure"):
        status = "failed"

    return {
        "timestamp": str(event.get("timestamp", "")),
        "user": str(event.get("user") or event.get("ip") or "unknown"),
        "ip": str(event.get("ip", "")),
        "status": status,
        "event_type": str(event.get("event_type", "")),
        "endpoint": str(event.get("endpoint", "")),
        "bytes": _to_int(event.get("bytes", 0)),
        "raw": event.get("raw", str(event)),
    }


# ── SSH / Auth log ──────────────────────────────────────────────
# e.g. Jan 10 08:12:01 server sshd[1234]: Failed password for admin from 1.2.3.4
AUTH_PATTERN = re.compile(
    r"(?P<timestamp>\w+\s+\d+\s[\d:]+).*?"
    r"(?P<status>Failed|Accepted|Invalid)\s+\w+\s+for\s+"
    r"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)"
)


def parse_auth_log(content: str) -> list[dict]:
    events = []
    for line in content.splitlines():
        m = AUTH_PATTERN.search(line)
        if m:
            events.append(normalize_event({
                "timestamp": m.group("timestamp"),
                "user": m.group("user"),
                "ip": m.group("ip"),
                "status": "failed" if m.group("status") in ("Failed", "Invalid") else "success",
                "event_type": "ssh_login",
                "endpoint": "ssh",
                "bytes": 0,
                "raw": line.strip(),
            }))
    return events


# ── Apache / Nginx access log ────────────────────────────────────
# e.g. 1.2.3.4 - user [10/Jan/2024:08:00:01 +0000] "GET /path HTTP/1.1" 200 512
ACCESS_PATTERN = re.compile(
    r'(?P<ip>[\d.]+)\s+-\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(?P<endpoint>\S+)[^"]*"\s+'
    r'(?P<status_code>\d{3})\s+(?P<bytes>\d+|-)'
)


def parse_access_log(content: str) -> list[dict]:
    events = []
    for line in content.splitlines():
        m = ACCESS_PATTERN.search(line)
        if m:
            code = int(m.group("status_code"))
            user = m.group("user") if m.group("user") != "-" else m.group("ip")
            events.append(normalize_event({
                "timestamp": m.group("timestamp"),
                "user": user,
                "ip": m.group("ip"),
                "status": "failed" if code in (401, 403) else "success",
                "event_type": "http_request",
                "endpoint": m.group("endpoint"),
                "bytes": int(m.group("bytes")) if m.group("bytes") != "-" else 0,
                "raw": line.strip(),
            }))
    return events


# ── CSV activity log ─────────────────────────────────────────────
# Expected columns: timestamp, user, ip, event_type, endpoint, status, bytes
def parse_csv_log(content: str) -> list[dict]:
    events = []
    reader = csv.DictReader(content.splitlines())
    for row in reader:
        events.append(normalize_event({
            "timestamp": row.get("timestamp", ""),
            "user": row.get("user", row.get("ip", "unknown")),
            "ip": row.get("ip", ""),
            "status": row.get("status", ""),
            "event_type": row.get("event_type", ""),
            "endpoint": row.get("endpoint", ""),
            "bytes": row.get("bytes", 0),
            "raw": str(row),
        }))
    return events


# ── JSON activity log ────────────────────────────────────────────
def parse_json_log(content: str) -> list[dict]:
    try:
        data = json.loads(content)
        if isinstance(data, list):
            return [normalize_event(event) for event in data if isinstance(event, dict)]
        return [normalize_event(data)]
    except json.JSONDecodeError:
        # Try NDJSON (one JSON object per line)
        events = []
        for line in content.splitlines():
            line = line.strip()
            if line:
                try:
                    parsed = json.loads(line)
                    if isinstance(parsed, dict):
                        events.append(normalize_event(parsed))
                except json.JSONDecodeError:
                    pass
        return events


def parse_file(filepath: str) -> list[dict]:
    """Auto-detect format and parse a log file."""
    path = Path(filepath)
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"Warning: Could not read {filepath}: {e}")
        return []

    suffix = path.suffix.lower()
    name = path.name.lower()

    if suffix == ".json":
        return parse_json_log(content)
    if suffix == ".csv":
        return parse_csv_log(content)
    if "access" in name or "nginx" in name or "apache" in name:
        return parse_access_log(content)
    if "auth" in name or "sshd" in name or "secure" in name:
        return parse_auth_log(content)

    # Try each parser and return the one with most hits
    parsers = [parse_auth_log, parse_access_log, parse_csv_log]
    results = [p(content) for p in parsers]
    return max(results, key=len)
