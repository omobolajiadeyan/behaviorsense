"""
Log parsers for common formats: SSH auth logs, web access logs, CSV activity logs.
Each parser returns a normalized list of event dicts.
"""

import re
import csv
import json
from pathlib import Path


class LogFileError(ValueError):
    """Raised when a log file cannot be read or contains no supported events."""


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
    event_fields = {
        "timestamp", "user", "ip", "status", "status_code",
        "event_type", "endpoint", "bytes",
    }

    def is_event(value):
        return isinstance(value, dict) and bool(event_fields.intersection(value))

    try:
        data = json.loads(content)
        if isinstance(data, list):
            return [normalize_event(event) for event in data if is_event(event)]
        if is_event(data):
            return [normalize_event(data)]
        return []
    except json.JSONDecodeError:
        # Try NDJSON (one JSON object per line)
        events = []
        for line in content.splitlines():
            line = line.strip()
            if line:
                try:
                    parsed = json.loads(line)
                    if is_event(parsed):
                        events.append(normalize_event(parsed))
                except json.JSONDecodeError:
                    pass
        return events


def _has_activity_csv_header(content: str) -> bool:
    try:
        header = next(csv.reader(content.splitlines()), [])
    except csv.Error:
        return False
    fields = {
        field.strip().lstrip("\ufeff").lower()
        for field in header
        if isinstance(field, str)
    }
    return "timestamp" in fields and bool(fields.intersection({"user", "ip"}))


def _parse_activity_csv(content: str, filepath: str) -> list[dict]:
    if not _has_activity_csv_header(content):
        raise LogFileError(f"'{filepath}' is not a supported activity CSV.")
    try:
        return parse_csv_log(content)
    except csv.Error as error:
        raise LogFileError(f"'{filepath}' contains invalid CSV data: {error}") from error


def parse_file(filepath: str) -> list[dict]:
    """Auto-detect format and parse a log file."""
    path = Path(filepath)
    try:
        content = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as e:
        raise LogFileError(f"Could not read '{filepath}': {e}") from e

    if not content.strip():
        raise LogFileError(f"'{filepath}' is empty.")

    suffix = path.suffix.lower()
    name = path.name.lower()

    if suffix == ".json":
        events = parse_json_log(content)
    elif suffix == ".csv":
        events = _parse_activity_csv(content, filepath)
    elif "access" in name or "nginx" in name or "apache" in name:
        events = parse_access_log(content)
    elif "auth" in name or "sshd" in name or "secure" in name:
        events = parse_auth_log(content)
    else:
        if AUTH_PATTERN.search(content):
            events = parse_auth_log(content)
        elif ACCESS_PATTERN.search(content):
            events = parse_access_log(content)
        elif _has_activity_csv_header(content):
            events = _parse_activity_csv(content, filepath)
        else:
            raise LogFileError(f"'{filepath}' has an unsupported log format.")

    if not events:
        raise LogFileError(f"'{filepath}' contains no supported events.")
    return events
