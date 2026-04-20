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

    # Normalise to 0-1 probability using sigmoid
    risk_score = round(sigmoid(weighted_sum - 1.5), 4)

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
