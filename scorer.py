"""
Anomaly scoring engine.
Computes a risk score for each entity by comparing their behavior
against the population baseline using z-score deviation analysis.
"""

import math
import statistics
from profiler import BehaviorProfile


def z_score(value: float, mean: float, std: float) -> float:
    if std == 0:
        return 0.0
    return abs((value - mean) / std)


def sigmoid(x: float) -> float:
    return 1 / (1 + math.exp(-x))


def compute_population_stats(profiles: dict[str, BehaviorProfile]) -> dict:
    """Compute mean and std for each metric across all entities."""
    all_failure_rates   = [p.failure_rate()      for p in profiles.values()]
    all_ip_diversity    = [p.ip_diversity()       for p in profiles.values()]
    all_ep_diversity    = [p.endpoint_diversity() for p in profiles.values()]
    all_avg_hours       = [p.avg_hour()           for p in profiles.values()]
    all_total_bytes     = [p.total_bytes()        for p in profiles.values()]
    all_event_counts    = [p.event_count          for p in profiles.values()]

    def safe_stats(data):
        if len(data) < 2:
            return statistics.mean(data) if data else 0.0, 1.0
        return statistics.mean(data), statistics.stdev(data) or 1.0

    return {
        "failure_rate":    safe_stats(all_failure_rates),
        "ip_diversity":    safe_stats(all_ip_diversity),
        "ep_diversity":    safe_stats(all_ep_diversity),
        "avg_hour":        safe_stats(all_avg_hours),
        "total_bytes":     safe_stats(all_total_bytes),
        "event_count":     safe_stats(all_event_counts),
    }


# How much each metric contributes to the final risk score.
METRIC_WEIGHTS = {
    "failure_rate":  0.35,   # High failure rate = brute force / credential stuffing
    "ip_diversity":  0.20,   # Many IPs = account sharing or distributed attack
    "ep_diversity":  0.15,   # Many endpoints = scanning / enumeration
    "avg_hour":      0.10,   # Unusual hours = suspicious
    "total_bytes":   0.15,   # High data volume = exfiltration
    "event_count":   0.05,   # Unusually high activity
}


TECHNIQUE_HINTS = {
    "failure_rate": {
        "id": "T1110",
        "name": "Brute Force",
        "why": "High authentication failure rate can indicate password guessing or credential stuffing.",
    },
    "ip_diversity": {
        "id": "T1078",
        "name": "Valid Accounts",
        "why": "One account or entity appearing from many IPs can indicate account sharing or compromise.",
    },
    "ep_diversity": {
        "id": "T1083",
        "name": "File and Directory Discovery",
        "why": "Broad endpoint access can indicate enumeration or discovery activity.",
    },
    "avg_hour": {
        "id": "T1078",
        "name": "Valid Accounts",
        "why": "Activity concentrated outside normal business hours can indicate suspicious account use.",
    },
    "total_bytes": {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "why": "Unusually high data volume can indicate collection or exfiltration behavior.",
    },
}


def security_signals(profile: BehaviorProfile) -> list[dict]:
    """Return interpretable security signals that supplement population z-scores."""
    signals = []

    if profile.failure_rate() >= 0.50 and profile.failed_logins >= 3:
        signals.append({
            "name": "high_failure_rate",
            "weight": 0.20,
            "metric": "failure_rate",
            "detail": f"{profile.failed_logins} failed events across {profile.event_count} total events",
        })
    if profile.ip_diversity() >= 5:
        signals.append({
            "name": "many_source_ips",
            "weight": 0.15,
            "metric": "ip_diversity",
            "detail": f"{profile.ip_diversity()} unique source IPs",
        })
    if profile.endpoint_diversity() >= 5:
        signals.append({
            "name": "broad_endpoint_access",
            "weight": 0.05,
            "metric": "ep_diversity",
            "detail": f"{profile.endpoint_diversity()} unique endpoints",
        })
    if profile.total_bytes() >= 5_000_000:
        signals.append({
            "name": "large_data_volume",
            "weight": 0.10,
            "metric": "total_bytes",
            "detail": f"{profile.total_bytes():,} bytes transferred",
        })
    if profile.event_count >= 10:
        signals.append({
            "name": "high_event_volume",
            "weight": 0.05,
            "metric": "event_count",
            "detail": f"{profile.event_count} events",
        })
    if profile.active_hours and (profile.avg_hour() < 6 or profile.avg_hour() > 22):
        signals.append({
            "name": "off_hours_activity",
            "weight": 0.10,
            "metric": "avg_hour",
            "detail": f"average activity hour {profile.avg_hour():.1f}",
        })

    return signals


def technique_hints(z_scores: dict, signals: list[dict]) -> list[dict]:
    metrics = [signal["metric"] for signal in signals]
    metrics.extend(metric for metric, z in z_scores.items() if z >= 2.5)

    hints = []
    seen = set()
    for metric in metrics:
        hint = TECHNIQUE_HINTS.get(metric)
        if not hint:
            continue
        key = (hint["id"], hint["name"])
        if key in seen:
            continue
        seen.add(key)
        hints.append(hint)
    return hints


def recommended_actions(signals: list[dict]) -> list[str]:
    names = {signal["name"] for signal in signals}
    actions = []
    if "high_failure_rate" in names:
        actions.append("Review authentication logs for password spraying, credential stuffing, and account lockout events.")
    if "many_source_ips" in names:
        actions.append("Check impossible-travel patterns and validate whether source IPs match expected user locations.")
    if "broad_endpoint_access" in names:
        actions.append("Review accessed endpoints for enumeration, discovery, or privilege misuse.")
    if "large_data_volume" in names:
        actions.append("Inspect transferred data volume and confirm whether the activity matches a legitimate business workflow.")
    if "off_hours_activity" in names:
        actions.append("Validate whether off-hours activity was expected for this user or service account.")
    if not actions:
        actions.append("Monitor this entity and compare against a larger historical baseline before escalating.")
    return actions


def score_entity(
    profile: BehaviorProfile,
    population_stats: dict,
) -> dict:
    """
    Score an entity's anomaly level (0.0 = normal, 1.0 = highly anomalous).
    Returns score breakdown per metric.
    """
    metrics = {
        "failure_rate":  profile.failure_rate(),
        "ip_diversity":  float(profile.ip_diversity()),
        "ep_diversity":  float(profile.endpoint_diversity()),
        "avg_hour":      profile.avg_hour(),
        "total_bytes":   float(profile.total_bytes()),
        "event_count":   float(profile.event_count),
    }

    z_scores = {}
    for metric, value in metrics.items():
        mean, std = population_stats[metric]
        z_scores[metric] = round(z_score(value, mean, std), 3)

    # Weighted sum of z-scores
    weighted_sum = sum(z_scores[m] * METRIC_WEIGHTS[m] for m in z_scores)
    signals = security_signals(profile)
    signal_boost = sum(signal["weight"] for signal in signals)

    # Normalize to 0-1 probability using sigmoid, then apply explicit security signal boosts.
    risk_score = round(min(1.0, sigmoid(weighted_sum - 1.5) + signal_boost), 4)

    return {
        "entity": profile.entity_id,
        "risk_score": risk_score,
        "risk_level": classify_risk(risk_score),
        "event_count": profile.event_count,
        "failed_logins": profile.failed_logins,
        "unique_ips": profile.ip_diversity(),
        "unique_endpoints": profile.endpoint_diversity(),
        "total_bytes": profile.total_bytes(),
        "z_scores": z_scores,
        "signals": signals,
        "technique_hints": technique_hints(z_scores, signals),
        "recommended_actions": recommended_actions(signals),
        "top_anomaly": max(z_scores, key=lambda k: z_scores[k] * METRIC_WEIGHTS[k]),
    }


def classify_risk(score: float) -> str:
    if score >= 0.80:
        return "CRITICAL"
    elif score >= 0.60:
        return "HIGH"
    elif score >= 0.40:
        return "MEDIUM"
    else:
        return "NORMAL"


def rank_entities(profiles: dict[str, BehaviorProfile]) -> list[dict]:
    """Score all entities and return sorted by risk score descending."""
    if not profiles:
        return []

    population_stats = compute_population_stats(profiles)
    scores = [score_entity(p, population_stats) for p in profiles.values()]
    return sorted(scores, key=lambda s: s["risk_score"], reverse=True)
