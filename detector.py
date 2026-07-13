#!/usr/bin/env python3
"""
BehaviorSense — behavioral anomaly detection for security logs.
Profiles every user and IP from log data, then uses statistical
deviation analysis to surface the most suspicious entities.
Author: Omobolaji Adeyan
"""

import argparse
import json
import os
import sys
from pathlib import Path
from parser import parse_file
from profiler import build_profiles
from scorer import rank_entities

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(errors="replace")

RED    = "\033[91m"
ORANGE = "\033[38;5;208m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
GRAY   = "\033[90m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

RISK_COLOR = {
    "CRITICAL": RED,
    "HIGH":     ORANGE,
    "MEDIUM":   YELLOW,
    "NORMAL":   GREEN,
}

RISK_BAR_LEN = 20


def risk_bar(score: float, level: str) -> str:
    color = RISK_COLOR.get(level, GRAY)
    filled = round(score * RISK_BAR_LEN)
    return color + "█" * filled + GRAY + "░" * (RISK_BAR_LEN - filled) + RESET + f"  {score*100:.1f}%"


def print_banner():
    print(f"""
{CYAN}{BOLD}
  ██████╗ ███████╗██╗  ██╗ █████╗ ██╗   ██╗██╗ ██████╗ ██████╗ ███████╗███████╗███╗   ██╗███████╗███████╗
  ██╔══██╗██╔════╝██║  ██║██╔══██╗██║   ██║██║██╔═══██╗██╔══██╗██╔════╝██╔════╝████╗  ██║██╔════╝██╔════╝
  ██████╔╝█████╗  ███████║███████║██║   ██║██║██║   ██║██████╔╝███████╗█████╗  ██╔██╗ ██║███████╗█████╗
  ██╔══██╗██╔══╝  ██╔══██║██╔══██║╚██╗ ██╔╝██║██║   ██║██╔══██╗╚════██║██╔══╝  ██║╚██╗██║╚════██║██╔══╝
  ██████╔╝███████╗██║  ██║██║  ██║ ╚████╔╝ ██║╚██████╔╝██║  ██║███████║███████╗██║ ╚████║███████║███████╗
  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝
{RESET}{GRAY}  Behavioral anomaly detection for security logs | github.com/omobolajiadeyan{RESET}
""")


def print_entity_card(result: dict, rank: int, verbose: bool = False):
    level = result["risk_level"]
    color = RISK_COLOR.get(level, GRAY)

    print(f"\n  {'─'*58}")
    print(f"  {BOLD}#{rank}  {color}{result['entity']}{RESET}  [{color}{level}{RESET}]")
    print(f"  Risk Score  : {risk_bar(result['risk_score'], level)}")
    print(f"  Events      : {result['event_count']}  |  Failed logins: {result['failed_logins']}")
    print(f"  Unique IPs  : {result['unique_ips']}  |  Endpoints: {result['unique_endpoints']}")
    if result["total_bytes"] > 0:
        print(f"  Data moved  : {result['total_bytes']:,} bytes")
    print(f"  Top anomaly : {YELLOW}{result['top_anomaly'].replace('_', ' ').title()}{RESET}")

    if verbose:
        print(f"\n  {GRAY}Z-score breakdown (deviation from population average):{RESET}")
        for metric, z in sorted(result["z_scores"].items(), key=lambda x: x[1], reverse=True):
            bar = "█" * min(int(z), 10)
            flag = f"  {RED}<<{RESET}" if z > 2.5 else ""
            print(f"    {metric:<20}: {z:5.2f}  {GRAY}{bar}{RESET}{flag}")

        if result.get("signals"):
            print(f"\n  {GRAY}Security signals:{RESET}")
            for signal in result["signals"]:
                print(f"    - {signal['name'].replace('_', ' ')}: {signal['detail']}")

        if result.get("technique_hints"):
            print(f"\n  {GRAY}Technique hints:{RESET}")
            for technique in result["technique_hints"]:
                print(f"    - {technique['id']} {technique['name']}: {technique['why']}")

        if result.get("recommended_actions"):
            print(f"\n  {GRAY}Recommended actions:{RESET}")
            for action in result["recommended_actions"]:
                print(f"    - {action}")


def print_summary(ranked: list[dict], total_events: int, total_entities: int):
    critical = sum(1 for r in ranked if r["risk_level"] == "CRITICAL")
    high = sum(1 for r in ranked if r["risk_level"] == "HIGH")
    medium = sum(1 for r in ranked if r["risk_level"] == "MEDIUM")
    normal = sum(1 for r in ranked if r["risk_level"] == "NORMAL")

    print(f"\n{'='*62}")
    print(f"{BOLD}  BEHAVIORSENSE REPORT{RESET}")
    print(f"{'='*62}")
    print(f"  Events analyzed   : {total_events:,}")
    print(f"  Entities profiled : {total_entities}")
    print(f"  {RED}CRITICAL          : {critical}{RESET}")
    print(f"  {ORANGE}HIGH              : {high}{RESET}")
    print(f"  {YELLOW}MEDIUM            : {medium}{RESET}")
    print(f"  {GREEN}NORMAL            : {normal}{RESET}")
    print(f"{'='*62}")


def collect_log_files(target: str) -> list[str]:
    path = Path(target)
    if path.is_file():
        return [str(path)]
    log_exts = {".log", ".txt", ".csv", ".json", ".out", ".access"}
    files = []
    for f in path.rglob("*"):
        if f.is_file() and (f.suffix in log_exts or "log" in f.name.lower()):
            files.append(str(f))
    return files


def main():
    parser = argparse.ArgumentParser(
        description="BehaviorSense — behavioral anomaly detection from security log data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python detector.py sample_data/                    # Analyze all sample logs
  python detector.py sample_data/activity.csv        # Single file
  python detector.py /var/log/ --top 10              # Top 10 riskiest entities
  python detector.py sample_data/ --verbose          # Show z-score breakdown
  python detector.py sample_data/ --output report.json
        """,
    )
    parser.add_argument("target", help="Log file or directory to analyze")
    parser.add_argument("--top", type=int, default=20, help="Show top N riskiest entities (default: 20)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show full z-score breakdown per entity")
    parser.add_argument("--output", "-o", help="Export results to JSON")
    parser.add_argument("--threshold", choices=["CRITICAL", "HIGH", "MEDIUM", "NORMAL"],
                        default="MEDIUM", help="Minimum risk level to display (default: MEDIUM)")

    args = parser.parse_args()

    if not os.path.exists(args.target):
        print(f"{RED}Error: '{args.target}' not found.{RESET}")
        sys.exit(1)

    print_banner()

    log_files = collect_log_files(args.target)
    if not log_files:
        print(f"{YELLOW}No log files found in '{args.target}'.{RESET}")
        sys.exit(0)

    print(f"{CYAN}Loading {len(log_files)} log file(s)...{RESET}")

    all_events = []
    for lf in log_files:
        events = parse_file(lf)
        all_events.extend(events)

    if not all_events:
        print(f"{YELLOW}No parseable events found.{RESET}")
        sys.exit(0)

    print(f"{CYAN}Profiling {len(all_events):,} events...{RESET}")
    profiles = build_profiles(all_events)
    ranked = rank_entities(profiles)

    # Filter by threshold
    threshold_order = ["CRITICAL", "HIGH", "MEDIUM", "NORMAL"]
    min_idx = threshold_order.index(args.threshold)
    filtered = [r for r in ranked if threshold_order.index(r["risk_level"]) <= min_idx]

    print_summary(ranked, len(all_events), len(profiles))

    display = filtered[:args.top]
    if not display:
        print(f"\n{GREEN}No entities above threshold '{args.threshold}'.{RESET}\n")
    else:
        print(f"\n{BOLD}TOP {len(display)} ENTITIES BY RISK SCORE{RESET}")
        for i, result in enumerate(display, 1):
            print_entity_card(result, i, verbose=args.verbose)

    print()

    if args.output:
        with open(args.output, "w") as f:
            json.dump({
                "total_events": len(all_events),
                "total_entities": len(profiles),
                "results": ranked,
            }, f, indent=2)
        print(f"{GREEN}Report saved to {args.output}{RESET}\n")

    if any(r["risk_level"] == "CRITICAL" for r in ranked):
        sys.exit(2)


if __name__ == "__main__":
    main()
