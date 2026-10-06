#!/usr/bin/env python3
"""Report batch CPU/query for the trusted Linux cpu_probe benchmark executable."""
import argparse
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import resource
import statistics
import subprocess

SCENARIOS = ("blocked", "cache", "temporary", "rewrite", "long-cache", "dnssec-cache")
FIELDS = ("scenario", "batch", "queries", "user_ticks", "system_ticks", "clock_hz", "wall_ns", "upstream_requests")


def parse_results(output, iterations, batches, scenarios, clock_hz):
    if len(output.encode()) > 65536:
        raise ValueError("probe output exceeds 64 KiB")
    reader = csv.DictReader(io.StringIO(output), delimiter="\t")
    if tuple(reader.fieldnames or ()) != FIELDS:
        raise ValueError("unexpected probe columns")
    rows = []
    seen = set()
    for row in reader:
        if len(rows) >= 30 or None in row or any(value is None for value in row.values()):
            raise ValueError("oversized or incomplete probe rows")
        if row["scenario"] not in scenarios:
            raise ValueError("unexpected scenario")
        values = {key: int(row[key]) for key in FIELDS[1:]}
        if any(value < 0 for value in values.values()):
            raise ValueError("negative probe accounting")
        if (values["queries"] != iterations or values["clock_hz"] != clock_hz
                or not 1 <= values["batch"] <= batches or values["wall_ns"] == 0
                or values["upstream_requests"] != 0):
            raise ValueError("query/clock/batch/upstream accounting mismatch")
        identity = (row["scenario"], values["batch"])
        if identity in seen:
            raise ValueError("duplicate probe batch")
        seen.add(identity)
        ticks = values["user_ticks"] + values["system_ticks"]
        estimate = ticks * 1e9 / clock_hz / iterations
        allowance = 2e9 / clock_hz / iterations
        # Coarse tick accounting can exceed a very short wall interval by
        # rounding. A larger discrepancy contradicts this single-thread probe.
        if ticks * 1e9 / clock_hz > values["wall_ns"] + 2e9 / clock_hz:
            raise ValueError("CPU exceeds single-thread wall accounting")
        rows.append({"scenario": row["scenario"], **values,
                     "cpu_ns_per_query": estimate if ticks >= 20 else None,
                     "low_precision": ticks < 20,
                     "rounding_allowance_ns_per_query": allowance,
                     "wall_ns_per_query": values["wall_ns"] / iterations})
    expected = {(scenario, batch) for scenario in scenarios for batch in range(1, batches + 1)}
    if seen != expected:
        raise ValueError("missing probe batches")
    return rows


def summarize(rows):
    result = {}
    for scenario in dict.fromkeys(row["scenario"] for row in rows):
        selected = [row for row in rows if row["scenario"] == scenario]
        precise = [row["cpu_ns_per_query"] for row in selected if not row["low_precision"]]
        result[scenario] = {
            "batches": len(selected), "queries": sum(row["queries"] for row in selected),
            "precise_batches": len(precise),
            # Do not select only the fastest/longest subset of noisy batches.
            "median_cpu_ns_per_query": statistics.median(precise) if len(precise) == len(selected) else None,
            "median_wall_ns_per_query": statistics.median(row["wall_ns_per_query"] for row in selected),
            "rounding_allowance_ns_per_query": max(row["rounding_allowance_ns_per_query"] for row in selected),
        }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/release/examples/cpu_probe"))
    parser.add_argument("--iterations", type=int, default=2_000_000)
    parser.add_argument("--batches", type=int, default=3)
    parser.add_argument("--scenario", choices=SCENARIOS)
    parser.add_argument("--cpu", type=int, help="pin only the benchmark process to an admitted CPU")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("CPU probe requires Linux")
    if not 10_000 <= args.iterations <= 5_000_000 or not 1 <= args.batches <= 5:
        parser.error("iterations must be 10000..5000000 and batches 1..5")
    affinity = sorted(os.sched_getaffinity(0))
    if args.cpu is not None and args.cpu not in affinity:
        parser.error("requested CPU is outside this process's allowed affinity")
    binary = args.binary.resolve(strict=True)
    command = [str(binary), "--iterations", str(args.iterations), "--batches", str(args.batches)]
    if args.scenario:
        command += ["--scenario", args.scenario]
    if args.cpu is not None:
        command = ["taskset", "-c", str(args.cpu), *command]
    before_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    process = subprocess.run(command, capture_output=True, text=True, check=True, timeout=300)
    peak_rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    if hashlib.sha256(binary.read_bytes()).hexdigest() != before_hash:
        raise ValueError("benchmark executable changed during measurement")
    scenarios = [args.scenario] if args.scenario else SCENARIOS
    rows = parse_results(process.stdout, args.iterations, args.batches, scenarios, os.sysconf("SC_CLK_TCK"))
    cpuinfo = Path("/proc/cpuinfo").read_text()
    model = next((line.split(":", 1)[1].strip() for line in cpuinfo.splitlines() if line.startswith("model name")), "unknown")
    try:
        host_rustc = subprocess.check_output(["rustc", "--version"], text=True, timeout=5).strip()
    except (FileNotFoundError, subprocess.SubprocessError):
        host_rustc = None
    report = {"format": 1, "binary": str(binary), "binary_sha256": before_hash,
              "command": command, "hardware": model, "os": platform.platform(),
              "host_rustc": host_rustc, "cpu_affinity": [args.cpu] if args.cpu is not None else affinity,
              "process_peak_rss_kib": peak_rss,
              "method": "process utime+stime ticks, single-thread warm wire loop including upstream guard; sampling/setup/reporting outside loop",
              "rows": rows, "summary": summarize(rows)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"output": str(args.output), "summary": report["summary"]}, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
