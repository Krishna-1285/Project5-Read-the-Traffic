#!/usr/bin/env python3
"""
flow_detector.py — Project 5: Read the Traffic
Student: Gokul Krishna

Run from project root:
python3 code/flow_detector.py code/baseline_flows.csv code/window_flows.csv --show-baseline
"""

from __future__ import annotations

import argparse
import csv
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

ADMIN_PORTS = {22, 445, 3389, 5985, 5986}


@dataclass(frozen=True)
class Flow:
    ts: datetime
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str
    bytes_out: int
    bytes_in: int
    note: str = ""


@dataclass
class HostProfile:
    src_ip: str
    p95_bytes_out: float
    normal_destinations: set[str] = field(default_factory=set)
    normal_ports: set[int] = field(default_factory=set)
    sample_count: int = 0


@dataclass
class Finding:
    anomaly_class: str
    host: str
    destination: str
    severity: str
    evidence: str
    recommendation: str


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def load_flows(csv_path: Path) -> list[Flow]:
    flows = []
    with csv_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(
            row for row in handle if row.strip() and not row.startswith("#")
        )
        for row in reader:
            if not row.get("src_ip"):
                continue
            flows.append(
                Flow(
                    ts=parse_timestamp(row["ts"]),
                    src_ip=row["src_ip"].strip(),
                    dst_ip=row["dst_ip"].strip(),
                    dst_port=int(row["dst_port"]),
                    proto=row["proto"].strip().lower(),
                    bytes_out=int(row["bytes_out"]),
                    bytes_in=int(row["bytes_in"]),
                    note=row.get("note", "").strip(),
                )
            )
    return flows


def percentile_95(values: list[int]) -> float:
    if not values:
        return 0.0
    if len(values) < 3:
        return float(max(values))

    ordered = sorted(values)
    rank = 0.95 * (len(ordered) - 1)
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = rank - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def build_profiles(baseline_flows: list[Flow]) -> dict[str, HostProfile]:
    bytes_by_host = defaultdict(list)
    dests_by_host = defaultdict(set)
    ports_by_host = defaultdict(set)

    for flow in baseline_flows:
        bytes_by_host[flow.src_ip].append(flow.bytes_out)
        dests_by_host[flow.src_ip].add(flow.dst_ip)
        ports_by_host[flow.src_ip].add(flow.dst_port)

    profiles = {}
    for host, byte_values in bytes_by_host.items():
        profiles[host] = HostProfile(
            src_ip=host,
            p95_bytes_out=percentile_95(byte_values),
            normal_destinations=dests_by_host[host],
            normal_ports=ports_by_host[host],
            sample_count=len(byte_values),
        )

    return profiles


def detect_exfiltration(
    window_flows: list[Flow],
    profiles: dict[str, HostProfile],
    multiplier: float,
    minimum_bytes: int,
) -> list[Finding]:
    findings = []

    for flow in window_flows:
        profile = profiles.get(flow.src_ip)
        baseline_p95 = profile.p95_bytes_out if profile else 10000.0
        threshold = max(minimum_bytes, baseline_p95 * multiplier)

        if flow.bytes_out > threshold:
            known_dst = profile and flow.dst_ip in profile.normal_destinations
            known_port = profile and flow.dst_port in profile.normal_ports

            findings.append(
                Finding(
                    anomaly_class="exfil",
                    host=flow.src_ip,
                    destination=f"{flow.dst_ip}:{flow.dst_port}",
                    severity="high",
                    evidence=(
                        f"bytes_out={flow.bytes_out:,} exceeded this host's p95 baseline "
                        f"of {baseline_p95:,.0f} by {flow.bytes_out / max(baseline_p95, 1):.1f}x. "
                        f"Destination normal for host: {known_dst}; port normal for host: {known_port}."
                    ),
                    recommendation=(
                        "Human-confirm immediately; block only after confirming destination "
                        "and business owner."
                    ),
                )
            )

    return findings


def detect_port_scan(
    window_flows: list[Flow],
    profiles: dict[str, HostProfile],
    minimum_destinations: int,
) -> list[Finding]:
    admin_hits = defaultdict(list)

    for flow in window_flows:
        if flow.dst_port in ADMIN_PORTS:
            admin_hits[flow.src_ip].append(flow)

    findings = []

    for src_ip, hits in admin_hits.items():
        destinations = sorted({flow.dst_ip for flow in hits})
        ports = sorted({flow.dst_port for flow in hits})
        profile = profiles.get(src_ip)
        normal_ports = profile.normal_ports if profile else set()
        unusual_ports = sorted(set(ports) - normal_ports)

        if len(destinations) >= minimum_destinations:
            first_ts = min(flow.ts for flow in hits)
            last_ts = max(flow.ts for flow in hits)
            burst_seconds = (last_ts - first_ts).total_seconds()

            findings.append(
                Finding(
                    anomaly_class="port_scan",
                    host=src_ip,
                    destination=f"{len(destinations)} hosts on ports {ports}",
                    severity="high",
                    evidence=(
                        f"{src_ip} contacted {len(destinations)} destinations on admin ports {ports} "
                        f"within {burst_seconds:.0f} seconds. Baseline normal ports for this host: "
                        f"{sorted(normal_ports) if normal_ports else 'no baseline profile'}; "
                        f"unusual admin ports observed: {unusual_ports}."
                    ),
                    recommendation=(
                        "Gate behind human approval; isolate host after confirming "
                        "no authorized admin scan."
                    ),
                )
            )

    return findings


def interval_stats(flows: list[Flow]) -> tuple[list[float], float, float]:
    ordered = sorted(flows, key=lambda item: item.ts)
    intervals = [
        (ordered[index].ts - ordered[index - 1].ts).total_seconds()
        for index in range(1, len(ordered))
    ]

    if not intervals:
        return [], 0.0, 0.0

    mean_interval = statistics.mean(intervals)
    jitter = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0

    return intervals, mean_interval, jitter


def detect_beaconing(
    window_flows: list[Flow],
    profiles: dict[str, HostProfile],
    minimum_hits: int,
    max_interval_jitter_seconds: float,
    max_byte_stdev: float,
) -> list[Finding]:
    groups = defaultdict(list)

    for flow in window_flows:
        groups[(flow.src_ip, flow.dst_ip, flow.dst_port)].append(flow)

    findings = []

    for (src_ip, dst_ip, dst_port), hits in groups.items():
        if len(hits) < minimum_hits:
            continue

        intervals, mean_interval, interval_jitter = interval_stats(hits)
        byte_values = [flow.bytes_out for flow in hits]
        byte_stdev = statistics.pstdev(byte_values) if len(byte_values) > 1 else 0.0

        profile = profiles.get(src_ip)
        known_destination = profile and dst_ip in profile.normal_destinations
        known_port = profile and dst_port in profile.normal_ports

        if interval_jitter <= max_interval_jitter_seconds and byte_stdev <= max_byte_stdev:
            findings.append(
                Finding(
                    anomaly_class="beaconing",
                    host=src_ip,
                    destination=f"{dst_ip}:{dst_port}",
                    severity="medium",
                    evidence=(
                        f"Same flow repeated {len(hits)} times with intervals {intervals}; "
                        f"mean interval={mean_interval:.0f}s, interval jitter={interval_jitter:.1f}s, "
                        f"bytes_out stdev={byte_stdev:.1f}. Destination normal for host: "
                        f"{known_destination}; port normal for host: {known_port}."
                    ),
                    recommendation="Investigate process and destination reputation before blocking.",
                )
            )

    return findings


def print_profiles(profiles: dict[str, HostProfile]) -> None:
    print("\nBASELINE PROFILE BY HOST")
    print("-" * 80)

    for host in sorted(profiles):
        profile = profiles[host]
        print(
            f"{host}: p95_bytes_out={profile.p95_bytes_out:,.0f}; "
            f"normal_destinations={sorted(profile.normal_destinations)}; "
            f"normal_ports={sorted(profile.normal_ports)}; "
            f"samples={profile.sample_count}"
        )


def print_findings(findings: list[Finding]) -> None:
    print("\nDETECTOR FINDINGS")
    print("-" * 80)

    if not findings:
        print("No candidate anomalies detected. Absence of a flag is not proof of safety.")
        return

    for number, finding in enumerate(findings, start=1):
        print(f"{number}. [{finding.anomaly_class.upper()}] {finding.host} -> {finding.destination}")
        print(f"   Severity: {finding.severity}")
        print(f"   Evidence: {finding.evidence}")
        print(f"   Recommendation: {finding.recommendation}")

    print(f"\nTotal candidate findings: {len(findings)}")
    print("Human confirmation is required before any disruptive response.")


def run_detector(args: argparse.Namespace) -> list[Finding]:
    baseline_flows = load_flows(Path(args.baseline_csv))
    window_flows = load_flows(Path(args.window_csv))
    profiles = build_profiles(baseline_flows)

    if args.show_baseline:
        print_profiles(profiles)

    findings = []
    findings.extend(
        detect_exfiltration(
            window_flows,
            profiles,
            multiplier=args.exfil_multiplier,
            minimum_bytes=args.exfil_min_bytes,
        )
    )
    findings.extend(
        detect_port_scan(
            window_flows,
            profiles,
            minimum_destinations=args.scan_min_destinations,
        )
    )
    findings.extend(
        detect_beaconing(
            window_flows,
            profiles,
            minimum_hits=args.beacon_min_hits,
            max_interval_jitter_seconds=args.beacon_max_interval_jitter,
            max_byte_stdev=args.beacon_max_byte_stdev,
        )
    )

    print_findings(findings)
    return findings


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a per-host baseline and detect exfiltration, port scanning, and beaconing."
    )

    parser.add_argument("baseline_csv", help="Path to code/baseline_flows.csv")
    parser.add_argument("window_csv", help="Path to code/window_flows.csv")

    parser.add_argument("--show-baseline", action="store_true")
    parser.add_argument("--exfil-multiplier", type=float, default=10.0)
    parser.add_argument("--exfil-min-bytes", type=int, default=1_000_000)
    parser.add_argument("--scan-min-destinations", type=int, default=4)
    parser.add_argument("--beacon-min-hits", type=int, default=4)
    parser.add_argument("--beacon-max-interval-jitter", type=float, default=2.0)
    parser.add_argument("--beacon-max-byte-stdev", type=float, default=50.0)

    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    run_detector(args)


if __name__ == "__main__":
    main()