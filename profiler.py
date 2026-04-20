"""
User/entity behavior profiling.
Builds a baseline profile from historical activity then scores deviations.
"""

import math
import statistics
from collections import defaultdict
from datetime import datetime


def parse_timestamp(ts: str) -> datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S"):
        try:
            return datetime.strptime(ts[:19], fmt)
        except ValueError:
            continue
    return None


class BehaviorProfile:
    """Tracks behavioral statistics for a single entity (user or IP)."""

    def __init__(self, entity_id: str):
        self.entity_id = entity_id
        self.event_count = 0
        self.failed_logins = 0
        self.unique_ips = set()
        self.unique_endpoints = set()
        self.active_hours: list[int] = []       # hours of day (0-23)
        self.bytes_transferred: list[int] = []
        self.session_durations: list[float] = []
        self.event_types: dict[str, int] = defaultdict(int)
        self.first_seen: datetime | None = None
        self.last_seen: datetime | None = None

    def ingest(self, event: dict):
        self.event_count += 1

        ts = parse_timestamp(event.get("timestamp", ""))
        if ts:
            if not self.first_seen or ts < self.first_seen:
                self.first_seen = ts
            if not self.last_seen or ts > self.last_seen:
                self.last_seen = ts
            self.active_hours.append(ts.hour)

        if event.get("status") in ("failed", "failure", "401", "403"):
            self.failed_logins += 1

        if event.get("ip"):
            self.unique_ips.add(event["ip"])

        if event.get("endpoint"):
            self.unique_endpoints.add(event["endpoint"])

        if event.get("bytes"):
            try:
                self.bytes_transferred.append(int(event["bytes"]))
            except (ValueError, TypeError):
                pass

        if event.get("event_type"):
            self.event_types[event["event_type"]] += 1

    def failure_rate(self) -> float:
        if self.event_count == 0:
            return 0.0
        return self.failed_logins / self.event_count

    def ip_diversity(self) -> int:
        return len(self.unique_ips)

    def endpoint_diversity(self) -> int:
        return len(self.unique_endpoints)

    def avg_hour(self) -> float:
        if not self.active_hours:
            return 12.0
        return statistics.mean(self.active_hours)

    def hour_std(self) -> float:
        if len(self.active_hours) < 2:
            return 0.0
        return statistics.stdev(self.active_hours)

    def avg_bytes(self) -> float:
        if not self.bytes_transferred:
            return 0.0
        return statistics.mean(self.bytes_transferred)

    def total_bytes(self) -> int:
        return sum(self.bytes_transferred)


def build_profiles(events: list[dict]) -> dict[str, BehaviorProfile]:
    """Build per-entity profiles from a list of parsed log events."""
    profiles: dict[str, BehaviorProfile] = {}

    for event in events:
        entity = event.get("user") or event.get("ip") or "unknown"
        if entity not in profiles:
            profiles[entity] = BehaviorProfile(entity)
        profiles[entity].ingest(event)

    return profiles
