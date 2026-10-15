#!/usr/bin/env python3
"""Reconcile four saved soak-driver artifacts offline; never establish provenance."""
import sys
# Loading the local helpers must not create Python bytecode cache files.
sys.dont_write_bytecode = True

import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat

_spec = importlib.util.spec_from_file_location("soak_evidence", Path(__file__).with_name("soak-evidence.py"))
e = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(e)
require = e.require
SUMMARY_KEYS = ("format run_id driver_passed failure completed elapsed_ms intended counts unoffered "
                "accounting_reconciled windows clients resources external_checks_unverified scope").split()
WINDOW_KEYS = ("run_id phase lane transport client window start_ms end_ms offer_start_ms offer_end_ms "
               "counts inflight_start inflight_end histogram resources completed_phase_counts last_generation").split()
LIMITATIONS = [
    "Internal consistency only; no aggregate run/source binding or authenticated provenance.",
    "Windows lack bins; exact window distributions and exact maxima cannot be reconstructed from bins.",
    "Completion origins combine replies/timeouts/errors; mixed-origin timeout attribution is unverified.",
    "No complete native DNS/run validation, representative path, authority, faults or long-run acceptance.",
]


def add_origins(left, right):
    for key, value in right.items():
        left[key] = e.u64(left.get(key, 0) + value)


def fold_resources(parts, value):
    parts["samples"] = e.u64(parts["samples"] + value["samples"])
    if not value["samples"]:
        return
    if parts["last"] is not None:
        require(parts["last"]["sequence"] < value["first"]["sequence"]
                and parts["last"]["unix_ms"] <= value["first"]["unix_ms"], "window sample continuity")
    if parts["first"] is None:
        parts["first"] = value["first"]
        parts["min"], parts["max"] = value["min"], value["max"]
    else:
        parts["min"] = list(map(min, parts["min"], value["min"]))
        parts["max"] = list(map(max, parts["max"], value["max"]))
    parts["last"] = value["last"]
    add_origins(parts["counter_deltas"], value["counter_deltas"])
    parts["counter_resets"] = e.u64(parts["counter_resets"] + value["counter_resets"])
    parts["resets"].extend(value["resets"])
    require(len(parts["resets"]) <= 16, "window reset evidence limit")


def empty_resources():
    return dict(samples=0, first=None, last=None, min=None, max=None,
                counter_deltas={}, counter_resets=0, resets=[])


def resource_coverage(parts, total, passed):
    require(parts["samples"] <= total["samples"], "window resource sample total")
    complete = parts["samples"] == total["samples"]
    if complete:
        require(parts == total, "window/global resource mismatch")
    elif parts["samples"]:
        # Failed execution may sample after its final work window without flushing again.
        require(parts["first"] == total["first"] and parts["last"]["sequence"] <= total["last"]["sequence"],
                "partial resource endpoints")
        require(all(a <= b and c <= d for a, b, c, d in
                    zip(total["min"], parts["min"], parts["max"], total["max"])), "partial resource extrema")
        require(all(k in total["counter_deltas"] and n <= total["counter_deltas"][k]
                    for k, n in parts["counter_deltas"].items()), "partial resource deltas")
        require(parts["resets"] == total["resets"][:len(parts["resets"])], "partial resource resets")
    require(not passed or complete, "passing run has incomplete window resources")
    return complete


class Inputs:
    def __init__(self, directory):
        self.directory = e.access.open_directory(directory)
        self.used = 0
        self.cap = 134217728

    def charge(self, count):
        self.used += count
        require(self.used <= self.cap, "selected artifact byte limit")

    def document(self, name, cap):
        value = e.access.read_regular(name, cap, self.directory)
        self.charge(len(value.encode("utf-8")))
        return e.parse(value)

    def windows(self, cap, lanes):
        descriptor = os.open("windows.ndjson", e.access.FILE_FLAGS, dir_fd=self.directory)
        try:
            require(stat.S_ISREG(os.fstat(descriptor).st_mode), "windows input is not regular")
            stream = os.fdopen(descriptor, "rb")
        except BaseException:
            os.close(descriptor)
            raise
        with stream:
            row = 0
            while True:
                line = stream.readline(cap + 1)
                if not line:
                    break
                self.charge(len(line))
                require(len(line) <= cap and line.endswith(b"\n"), "oversized or partial window line")
                row += 1
                require(row <= 4320 * lanes, "window row limit")
                yield e.parse(line.decode("utf-8"))


def check_windows(inputs, run, phases, summary, aggregate):
    lanes = run["lanes"]
    generations = {g for p, _, _ in phases.values() for g in p["generations"]}
    totals = [e.zeros() for _ in lanes]
    origins = [{} for _ in lanes]
    maxima, clipped, pending = [0] * len(lanes), [0] * len(lanes), [0] * len(lanes)
    single_reply_window = [None] * len(lanes)
    resources = empty_resources()
    dispatch = {name: [e.zeros() for _ in lanes] for name in phases}
    group, rows, previous_end, previous_phase = None, 0, 0, 0
    phase_order = list(phases)
    for row in inputs.windows(run["limits"]["window_bytes"], len(lanes)):
        e.shape(row, WINDOW_KEYS)
        index, lane_index = divmod(rows, len(lanes))
        lane = lanes[lane_index]
        require(e.number(row["window"], 0, 4319) == index and row["run_id"] == run["run_id"]
                and row["lane"] == lane["id"] and row["transport"] == lane["transport"]
                and row["client"] == run["clients"][lane["client"]]["id"], "window identity/order mismatch")
        require(type(row["phase"]) is str and row["phase"] in phases, "window phase")
        phase, start, end = phases[row["phase"]]
        phase_index = phase_order.index(phase["id"])
        require(e.u64(row["offer_start_ms"]) == start and e.u64(row["offer_end_ms"]) == end,
                "window planned offer interval")
        require(e.u64(row["start_ms"]) <= e.u64(row["end_ms"]) <= summary["elapsed_ms"], "window time range")
        require(row["end_ms"] >= start, "window precedes dispatch phase")
        require(row["last_generation"] is None or e.u64(row["last_generation"]) in generations,
                "window generation")
        e.resource_summary(row["resources"], run, generations, set(phase["generations"]))
        if row["resources"]["samples"]:
            require(row["last_generation"] == row["resources"]["last"]["generation"], "last sampled generation mismatch")
        if lane_index == 0:
            require(row["start_ms"] == previous_end and phase_index >= previous_phase,
                    "window time/phase continuity")
            if phase_index > previous_phase:
                require(previous_end >= phases[phase_order[previous_phase]][2], "phase advanced before offer interval ended")
            group = row
            previous_end, previous_phase = row["end_ms"], phase_index
            fold_resources(resources, row["resources"])
            inflight_start = 0
        else:
            for key in ("phase", "start_ms", "end_ms", "offer_start_ms", "offer_end_ms", "resources", "last_generation"):
                require(row[key] == group[key], "inconsistent window lane copies")
        count = e.counts(row["counts"])
        before = e.number(row["inflight_start"], 0, run["limits"]["outstanding"])
        after = e.number(row["inflight_end"], 0, run["limits"]["outstanding"])
        require(before == pending[lane_index] and count["offered"] == e.u64(count["sent"] + count["skipped"])
                and e.u64(before + count["sent"]) == e.u64(sum(count[k] for k in
                    ("replies", "timeouts", "errors", "cancelled")) + after), "window accounting/inflight mismatch")
        pending[lane_index] = after
        inflight_start += before
        e.quantiles(row["histogram"], count)
        if count["replies"]:
            bins = aggregate["lanes"][lane_index]["histogram"]["bins"]
            require(all(bins[e.bucket(row["histogram"][key])] > 0 for key in
                        ("p50_us", "p95_us", "p99_us", "p999_us", "max_us")), "window value occupies absent aggregate bin")
        if count["replies"]:
            single_reply_window[lane_index] = (row["histogram"] if single_reply_window[lane_index] is None else False)
        completed = e.u64(sum(count[k] for k in ("replies", "timeouts", "errors")))
        origin = e.origins(row["completed_phase_counts"], phases, completed)
        require(all(phase_order.index(key) <= phase_index for key in origin), "future completion origin")
        if summary["driver_passed"]:
            allowed = sum(n for key, n in origin.items() if phases[key][0]["allow_timeouts"])
            require(count["timeouts"] <= allowed, "passing timeouts exceed allowed-origin capacity")
        totals[lane_index] = e.add(totals[lane_index], count)
        dispatch[phase["id"]][lane_index] = e.add(dispatch[phase["id"]][lane_index], count)
        add_origins(origins[lane_index], origin)
        maxima[lane_index] = max(maxima[lane_index], row["histogram"]["max_us"])
        clipped[lane_index] = e.u64(clipped[lane_index] + row["histogram"]["latencies_clipped"])
        rows += 1
        if lane_index + 1 == len(lanes):
            require(inflight_start <= run["limits"]["outstanding"] and sum(pending) <= run["limits"]["outstanding"],
                    "global inflight bound")
    require(rows % len(lanes) == 0 and rows // len(lanes) == summary["windows"], "incomplete window coverage")
    require(not any(pending), "incomplete final inflight drain")
    weight = sum(lane["weight"] for lane in lanes)
    for name, (phase, _, _) in phases.items():
        offered = sum(count["offered"] for count in dispatch[name])
        require(offered <= phase["seconds"] * phase["qps"], "phase workload bound")
        prefix = 0
        for index, lane in enumerate(lanes):
            lane_count = dispatch[name][index]
            expected = offered // weight * lane["weight"] + min(max(offered % weight - prefix, 0), lane["weight"])
            require(lane_count["offered"] == expected and origins[index].get(name, 0) <= lane_count["sent"],
                    "weighted lane prefix/origin capacity")
            if summary["driver_passed"]:
                require(origins[index].get(name, 0) == lane_count["sent"], "passing lane origin coverage")
            prefix += lane["weight"]
        if summary["driver_passed"]:
            require(offered == phase["seconds"] * phase["qps"], "passing phase workload coverage")
    if summary["driver_passed"]:
        require(previous_end == summary["elapsed_ms"] and previous_phase == len(phases) - 1,
                "passing window phase/duration coverage")
    return totals, origins, maxima, clipped, resources, single_reply_window


def verify(directory):
    inputs = Inputs(directory)
    try:
        run = inputs.document("run.json", 262144)
        phases = e.run_record(run)
        inputs.cap = run["limits"]["artifact_bytes"]
        summary = e.shape(inputs.document("summary.json", 65536), SUMMARY_KEYS)
        require(e.number(summary["format"]) == 1 and summary["run_id"] == run["run_id"], "summary identity/version")
        for key in ("driver_passed", "completed", "accounting_reconciled"):
            e.boolean(summary[key])
        for key in ("elapsed_ms", "intended", "unoffered"):
            e.u64(summary[key])
        e.number(summary["windows"], 0, 4320)
        e.text(summary["scope"], 2048)
        if summary["failure"] is not None:
            e.text(summary["failure"], 4096)
        require(summary["driver_passed"] == (summary["failure"] is None), "pass/failure mismatch")
        require(summary["external_checks_unverified"] == run["external_checks"], "external checks mismatch")
        expected = e.u64(sum(p["seconds"] * p["qps"] for p, _, _ in phases.values()))
        count = e.counts(summary["counts"])
        require(summary["intended"] == expected and count["offered"] <= expected
                and summary["unoffered"] == expected - count["offered"]
                and summary["accounting_reconciled"] and e.reconciled(count), "summary accounting mismatch")
        if summary["completed"]:
            require(count["offered"] == expected and summary["elapsed_ms"] >= sum(p["seconds"] * 1000 for p, _, _ in phases.values()),
                    "completed interval/count mismatch")
        generations = {g for p, _, _ in phases.values() for g in p["generations"]}
        e.resource_summary(summary["resources"], run, generations)
        e.global_resource_semantics(summary["resources"])
        aggregate = e.shape(inputs.document("aggregate.json", run["limits"]["aggregate_bytes"]), ["precision", "lanes"])
        require(aggregate["precision"] == e.PRECISION, "unsupported histogram precision")
        e.array(aggregate["lanes"], len(run["lanes"]), len(run["lanes"]))
        for lane, entry in zip(run["lanes"], aggregate["lanes"]):
            e.shape(entry, "lane transport counts quantiles histogram completed_phase_counts".split())
            require(entry["lane"] == lane["id"] and entry["transport"] == lane["transport"], "aggregate lane identity/order")
            e.histogram(entry["histogram"], e.counts(entry["counts"]), entry["quantiles"])
        windows, origins, maxima, clipped, parts, single = check_windows(inputs, run, phases, summary, aggregate)
        totals, clients = e.zeros(), [e.zeros() for _ in run["clients"]]
        for index, (lane, entry) in enumerate(zip(run["lanes"], aggregate["lanes"])):
            lane_count = e.counts(entry["counts"])
            require(lane_count == windows[index] and e.reconciled(lane_count), "aggregate/window count mismatch")
            e.origins(entry["completed_phase_counts"], phases,
                      e.u64(sum(lane_count[k] for k in ("replies", "timeouts", "errors"))))
            require(entry["completed_phase_counts"] == origins[index], "aggregate/window origins mismatch")
            if single[index]:
                require(all(single[index][key] == entry["quantiles"][key]
                            for key in ("p50_us", "p95_us", "p99_us", "p999_us")), "single-window quantile mismatch")
            require(entry["histogram"]["max_us"] == maxima[index] and entry["histogram"]["clipped"] == clipped[index],
                    "aggregate/window latency scalar mismatch")
            totals = e.add(totals, lane_count)
            clients[lane["client"]] = e.add(clients[lane["client"]], lane_count)
        require(totals == count, "summary/aggregate count mismatch")
        e.array(summary["clients"], len(clients), len(clients))
        for client, expected_count, actual in zip(run["clients"], clients, summary["clients"]):
            e.shape(actual, ["client", "counts"])
            require(actual["client"] == client["id"] and e.counts(actual["counts"]) == expected_count,
                    "client totals/identity mismatch")
        covered = resource_coverage(parts, summary["resources"], summary["driver_passed"])
        if summary["driver_passed"]:
            require(summary["completed"] and summary["resources"]["samples"] > 0
                    and all(entry["counts"]["replies"] > 0 for entry in aggregate["lanes"])
                    and all(count[k] == 0 for k in ("wrong", "skipped", "cancelled", "errors")), "unsupported passing result")
            require(all(entry["histogram"]["clipped"] == 0 and entry["histogram"]["max_us"] <= run["limits"]["latency_us"]
                        for entry in aggregate["lanes"]), "passing latency budget mismatch")
        return {"format": 1, "run_id": run["run_id"], "evidence_consistent": True,
                "driver_passed": summary["driver_passed"], "completed": summary["completed"],
                "counts": count, "windows": summary["windows"], "resource_windows_complete": covered,
                "external_checks_unverified": run["external_checks"], "limitations": LIMITATIONS}
    finally:
        os.close(inputs.directory)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = verify(args.directory)
        payload = json.dumps(result, separators=(",", ":"), allow_nan=False, ensure_ascii=False)
        require(len(payload.encode("utf-8")) <= 65536, "verifier output bound")
        print(payload)
        return 0 if result["driver_passed"] else 2
    except (e.access.CollectionError, OSError, ValueError, RecursionError):
        print('{"evidence_consistent":false,"error":"invalid or incomplete driver evidence"}')
        return 1


if __name__ == "__main__":
    sys.exit(main())
