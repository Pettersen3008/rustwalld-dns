import copy
import importlib.util
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/verify-soak.py"
spec = importlib.util.spec_from_file_location("verify_soak", SCRIPT)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
e = verifier.e


def fixture():
    run = json.loads((ROOT / "fuzz/seeds/soak_record/run.json").read_text())
    count = dict(offered=10, sent=10, replies=10, timeouts=0, errors=0, wrong=0, skipped=0, cancelled=0)
    sample = dict(run_id=run["run_id"], target_id=run["collector"]["target_id"], process_id="123:456",
                  sequence=0, unix_ms=1000, generation=1, resources=[1] * 6, counters={"requests": 0})
    resource = dict(samples=1, first=sample, last=copy.deepcopy(sample), min=[1] * 6, max=[1] * 6,
                    counter_deltas={}, counter_resets=0, resets=[])
    report = dict(replies=10, timeouts=0, incorrect=0, latencies_clipped=0, max_us=1,
                  p50_us=1, p95_us=1, p99_us=1, p999_us=1)
    bins = [0] * 21001
    bins[1] = 10
    lane = dict(lane="lane-0", transport="udp", counts=copy.deepcopy(count), quantiles=copy.deepcopy(report),
                histogram=dict(bins=bins, replies=10, timeouts=0, incorrect=0, clipped=0, max_us=1),
                completed_phase_counts={"steady": 10})
    window = dict(run_id=run["run_id"], phase="steady", lane="lane-0", transport="udp", client="client-1",
                  window=0, start_ms=0, end_ms=1000, offer_start_ms=0, offer_end_ms=1000,
                  counts=copy.deepcopy(count), inflight_start=0, inflight_end=0, histogram=copy.deepcopy(report),
                  resources=copy.deepcopy(resource), completed_phase_counts={"steady": 10}, last_generation=1)
    summary = dict(format=1, run_id=run["run_id"], driver_passed=True, failure=None, completed=True,
                   elapsed_ms=1000, intended=10, counts=count, unoffered=0, accounting_reconciled=True,
                   windows=1, clients=[dict(client="client-1", counts=copy.deepcopy(count))],
                   resources=resource, external_checks_unverified=run["external_checks"], scope="fixture only")
    return {"run.json": run, "summary.json": summary,
            "aggregate.json": {"precision": e.PRECISION, "lanes": [lane]}, "windows.ndjson": [window]}


def save(root, bundle):
    for name, value in bundle.items():
        text = ("".join(json.dumps(row, separators=(",", ":")) + "\n" for row in value)
                if name.endswith("ndjson") else json.dumps(value, separators=(",", ":")))
        (root / name).write_text(text)


def set_path(bundle, path, value):
    target = bundle
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value


def multiwindow():
    bundle = fixture()
    run, summary = bundle["run.json"], bundle["summary.json"]
    run["phases"][0]["qps"] = 5
    second_phase = copy.deepcopy(run["phases"][0])
    second_phase["id"] = "next"
    run["phases"].append(second_phase)
    first = bundle["windows.ndjson"][0]
    first["counts"].update(offered=5, sent=5, replies=4)
    first["histogram"]["replies"] = 4
    first["inflight_end"] = 1
    first["completed_phase_counts"] = {"steady": 4}
    second = copy.deepcopy(first)
    second.update(window=1, phase="next", start_ms=1000, end_ms=2000, offer_start_ms=1000,
                  offer_end_ms=2000, inflight_start=1, inflight_end=0,
                  completed_phase_counts={"steady": 1, "next": 5})
    second["counts"]["replies"] = 6
    second["histogram"]["replies"] = 6
    snapshot = second["resources"]["first"]
    snapshot.update(sequence=2, unix_ms=2000, counters={"requests": 10})
    second["resources"]["last"] = copy.deepcopy(snapshot)
    second["resources"]["counter_deltas"] = {"requests": 10}
    bundle["windows.ndjson"].append(second)
    summary.update(windows=2, elapsed_ms=2000)
    summary["resources"].update(samples=2, last=copy.deepcopy(snapshot), counter_deltas={"requests": 10})
    bundle["aggregate.json"]["lanes"][0]["completed_phase_counts"] = {"steady": 5, "next": 5}
    return bundle


class Evidence(unittest.TestCase):
    def verify_bundle(self, bundle):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            save(root, bundle)
            return verifier.verify(root)

    def test_valid_fixture_and_cross_phase_inflight_resource_deltas(self):
        self.assertTrue(self.verify_bundle(fixture())["driver_passed"])
        report = self.verify_bundle(multiwindow())
        self.assertTrue(report["driver_passed"])
        self.assertTrue(report["resource_windows_complete"])
        self.assertEqual(report["counts"]["replies"], 10)

    def test_zero_query_failed_run_can_retain_initial_sample(self):
        bundle = fixture()
        summary, lane = bundle["summary.json"], bundle["aggregate.json"]["lanes"][0]
        summary.update(driver_passed=False, completed=False, failure="cancelled", elapsed_ms=0,
                       windows=0, counts=e.zeros(), unoffered=10)
        summary["clients"][0]["counts"] = e.zeros()
        lane.update(counts=e.zeros(), completed_phase_counts={})
        lane["histogram"].update(bins=[0] * 21001, replies=0, max_us=0)
        lane["quantiles"] = dict.fromkeys(e.QUANTILE_KEYS, 0)
        bundle["windows.ndjson"] = []
        result = self.verify_bundle(bundle)
        self.assertFalse(result["driver_passed"])
        self.assertFalse(result["resource_windows_complete"])

    def test_weighted_prefix_and_per_lane_origin_capacity_prevent_reassignment(self):
        bundle = multiwindow()
        run, aggregate = bundle["run.json"], bundle["aggregate.json"]
        other = copy.deepcopy(run["lanes"][0])
        other["id"] = "lane-1"
        run["lanes"].append(other)
        windows = []
        for phase_index, original in enumerate(bundle["windows.ndjson"]):
            for lane_index, offered in enumerate((3, 2)):
                row = copy.deepcopy(original)
                row["lane"] = f"lane-{lane_index}"
                replies = offered - 1 if phase_index == 0 else offered + 1
                row["counts"].update(offered=offered, sent=offered, replies=replies)
                row["histogram"]["replies"] = replies
                row.update(inflight_start=phase_index, inflight_end=1 - phase_index)
                row["completed_phase_counts"] = ({"steady": replies} if phase_index == 0
                                                  else {"steady": 1, "next": offered})
                windows.append(row)
        bundle["windows.ndjson"] = windows
        for lane_index, count in enumerate((6, 4)):
            entry = (aggregate["lanes"][0] if lane_index == 0 else copy.deepcopy(aggregate["lanes"][0]))
            entry["lane"] = f"lane-{lane_index}"
            entry["counts"].update(offered=count, sent=count, replies=count)
            entry["histogram"]["replies"] = count
            entry["histogram"]["bins"][1] = count
            entry["quantiles"]["replies"] = count
            entry["completed_phase_counts"] = {"steady": count // 2, "next": count // 2}
            if lane_index:
                aggregate["lanes"].append(entry)
        self.assertTrue(self.verify_bundle(bundle)["driver_passed"])
        original = copy.deepcopy(bundle)
        windows[2]["completed_phase_counts"] = {"steady": 2, "next": 2}
        windows[3]["completed_phase_counts"] = {"next": 3}
        aggregate["lanes"][0]["completed_phase_counts"] = {"steady": 4, "next": 2}
        aggregate["lanes"][1]["completed_phase_counts"] = {"steady": 1, "next": 3}
        with self.assertRaises(e.access.CollectionError):
            self.verify_bundle(bundle)
        bundle = original
        # The first phase's five slots allocate 3/2, not 2/3; totals still sum to five.
        bundle["windows.ndjson"][0]["counts"].update(offered=2, sent=2, replies=1)
        bundle["windows.ndjson"][0]["histogram"]["replies"] = 1
        bundle["windows.ndjson"][0]["completed_phase_counts"] = {"steady": 1}
        bundle["windows.ndjson"][1]["counts"].update(offered=3, sent=3, replies=2)
        bundle["windows.ndjson"][1]["histogram"]["replies"] = 2
        bundle["windows.ndjson"][1]["completed_phase_counts"] = {"steady": 2}
        with self.assertRaisesRegex(e.access.CollectionError, "weighted lane prefix"):
            self.verify_bundle(bundle)

    def test_completion_is_not_inferred_from_all_offered_work(self):
        bundle = fixture()
        bundle["summary.json"].update(driver_passed=False, completed=False, failure="cancelled", elapsed_ms=999)
        bundle["windows.ndjson"][0]["end_ms"] = 999
        report = self.verify_bundle(bundle)
        self.assertFalse(report["completed"])
        self.assertEqual(report["counts"]["offered"], 10)

    def test_phase_boundary_cannot_advance_before_previous_offered_interval_ends(self):
        bundle = multiwindow()
        bundle["windows.ndjson"][0]["end_ms"] = 500
        bundle["windows.ndjson"][1]["start_ms"] = 500
        with self.assertRaises(e.access.CollectionError):
            self.verify_bundle(bundle)

    def test_window_quantiles_must_use_representable_native_bucket_values(self):
        bundle = multiwindow()
        for row in bundle["windows.ndjson"]:
            row["histogram"].update(max_us=1101, p50_us=1101, p95_us=1200, p99_us=1200, p999_us=1200)
        lane = bundle["aggregate.json"]["lanes"][0]
        lane["histogram"].update(bins=[0] * 21001, max_us=1101)
        lane["histogram"]["bins"][1002] = 10
        lane["quantiles"].update(max_us=1101, p50_us=1200, p95_us=1200, p99_us=1200, p999_us=1200)
        with self.assertRaises(e.access.CollectionError):
            self.verify_bundle(bundle)

    def test_initial_global_single_sample_cannot_claim_counter_deltas_or_resets(self):
        for delta, resets in [({"requests": 999999}, []),
                              ({}, [dict(from_process="123:456", to_process="123:456", from_generation=1,
                                         to_generation=1, counters=["requests"])])]:
            bundle = fixture()
            resource = bundle["summary.json"]["resources"]
            resource.update(counter_deltas=delta, resets=resets, counter_resets=len(resets))
            bundle["windows.ndjson"][0]["resources"] = copy.deepcopy(resource)
            with self.assertRaises(e.access.CollectionError):
                self.verify_bundle(bundle)

    def test_global_no_reset_counter_deltas_equal_endpoint_differences(self):
        bundle = multiwindow()
        bundle["summary.json"]["resources"]["counter_deltas"] = {"requests": 999999}
        bundle["windows.ndjson"][1]["resources"]["counter_deltas"] = {"requests": 999999}
        with self.assertRaises(e.access.CollectionError):
            self.verify_bundle(bundle)

    def test_window_new_samples_must_belong_to_dispatch_phase_generations(self):
        bundle = multiwindow()
        bundle["run.json"]["phases"][1]["generations"] = [2]
        with self.assertRaises(e.access.CollectionError):
            self.verify_bundle(bundle)
        reset = dict(from_process="123:456", to_process="123:456", from_generation=1,
                     to_generation=2, counters=["requests"])
        summary_resource = bundle["summary.json"]["resources"]
        window_resource = bundle["windows.ndjson"][1]["resources"]
        summary_resource["last"]["generation"] = 2
        window_resource["first"]["generation"] = 2
        window_resource["last"]["generation"] = 2
        bundle["windows.ndjson"][1]["last_generation"] = 2
        for resource in (summary_resource, window_resource):
            resource.update(counter_deltas={}, counter_resets=1, resets=[copy.deepcopy(reset)])
        # The reset's old generation belongs to the previous phase, while both new samples belong to this one.
        self.assertTrue(self.verify_bundle(bundle)["driver_passed"])
        for resource in (summary_resource, bundle["windows.ndjson"][0]["resources"], window_resource):
            for snapshot in (resource["first"], resource["last"]):
                snapshot["counters"].update(cache_hits=0, history_failures=0)
        for resource in (summary_resource, window_resource):
            resource["counter_resets"] = 3
            resource["resets"][0]["counters"] = ["cache_hits", "history_failures", "requests"]
        # One event can affect more counters than the number of observations.
        self.assertTrue(self.verify_bundle(bundle)["driver_passed"])

    def test_window_quantiles_must_occupy_aggregate_bins_without_reconstructing_distributions(self):
        bundle = multiwindow()
        bundle["windows.ndjson"][0]["histogram"]["p50_us"] = 0
        with self.assertRaises(e.access.CollectionError):
            self.verify_bundle(bundle)

    def test_two_global_samples_have_one_exact_native_counter_transition(self):
        bundle = multiwindow()
        reset = dict(from_process="123:456", to_process="123:456", from_generation=1,
                     to_generation=1, counters=["requests"])
        for resource in (bundle["summary.json"]["resources"], bundle["windows.ndjson"][1]["resources"]):
            resource.update(counter_deltas={}, counter_resets=1, resets=[copy.deepcopy(reset)])
        with self.assertRaises(e.access.CollectionError):
            self.verify_bundle(bundle)
        bundle["summary.json"]["resources"]["first"]["counters"]["requests"] = 10
        for snapshot in (bundle["windows.ndjson"][0]["resources"]["first"],
                         bundle["windows.ndjson"][0]["resources"]["last"]):
            snapshot["counters"]["requests"] = 10
        for snapshot in (bundle["summary.json"]["resources"]["last"],
                         bundle["windows.ndjson"][1]["resources"]["first"],
                         bundle["windows.ndjson"][1]["resources"]["last"]):
            snapshot["counters"]["requests"] = 0
        self.assertTrue(self.verify_bundle(bundle)["driver_passed"])
        impossible_extrema = copy.deepcopy(bundle["summary.json"]["resources"])
        impossible_extrema["max"][0] = 2
        with self.assertRaises(e.access.CollectionError):
            e.global_resource_semantics(impossible_extrema)

    def test_reset_event_count_is_bounded_by_observed_transitions(self):
        for event_count in (2, 3):
            bundle = multiwindow()
            first = bundle["windows.ndjson"][0]["resources"]
            first.update(samples=2, counter_deltas={"requests": 0})
            first["last"].update(sequence=1, unix_ms=1500)
            reset = dict(from_process="123:456", to_process="123:456", from_generation=1,
                         to_generation=1, counters=["requests"])
            for resource in (bundle["summary.json"]["resources"], bundle["windows.ndjson"][1]["resources"]):
                resource.update(counter_deltas={"requests": 0} if resource is bundle["summary.json"]["resources"] else {},
                                counter_resets=event_count, resets=[copy.deepcopy(reset) for _ in range(event_count)])
            bundle["summary.json"]["resources"]["samples"] = 3
            with self.subTest(event_count=event_count), self.assertRaises(e.access.CollectionError):
                self.verify_bundle(bundle)

    def test_mixed_origin_timeout_capacity_uses_origins_not_dispatch_label(self):
        bundle = multiwindow()
        bundle["run.json"]["phases"][0]["allow_timeouts"] = True
        summary, lane, window = bundle["summary.json"], bundle["aggregate.json"]["lanes"][0], bundle["windows.ndjson"][1]
        for count in (summary["counts"], summary["clients"][0]["counts"], lane["counts"]):
            count.update(replies=9, timeouts=1)
        window["counts"].update(replies=5, timeouts=1)
        window["histogram"].update(replies=5, timeouts=1)
        lane["quantiles"].update(replies=9, timeouts=1)
        lane["histogram"].update(replies=9, timeouts=1)
        lane["histogram"]["bins"][1] = 9
        self.assertTrue(self.verify_bundle(bundle)["driver_passed"])
        bundle["run.json"]["phases"][0]["allow_timeouts"] = False
        with self.assertRaises(e.access.CollectionError):
            self.verify_bundle(bundle)

    def test_each_identity_accounting_histogram_and_resource_tamper_is_rejected(self):
        mutations = [
            (("summary.json", "run_id"), "other"),
            (("summary.json", "counts", "sent"), 11),
            (("summary.json", "counts", "replies"), True),
            (("summary.json", "counts", "offered"), 1 << 64),
            (("summary.json", "clients", 0, "client"), "other"),
            (("summary.json", "clients", 0, "counts", "replies"), 9),
            (("summary.json", "windows"), 2),
            (("summary.json", "unoffered"), 1),
            (("summary.json", "resources", "last", "target_id"), "other"),
            (("summary.json", "resources", "max", 0), 999999),
            (("summary.json", "external_checks_unverified"), []),
            (("aggregate.json", "lanes", 0, "lane"), "other"),
            (("aggregate.json", "lanes", 0, "histogram", "bins", 1), 9),
            (("aggregate.json", "lanes", 0, "histogram", "bins", 21000), 1),
            (("aggregate.json", "lanes", 0, "histogram", "bins", 1), False),
            (("aggregate.json", "lanes", 0, "quantiles", "p99_us"), 0),
            (("aggregate.json", "lanes", 0, "completed_phase_counts"), {"unknown": 10}),
            (("windows.ndjson", 0, "run_id"), "other"),
            (("windows.ndjson", 0, "client"), "other"),
            (("windows.ndjson", 0, "transport"), "tcp"),
            (("windows.ndjson", 0, "window"), 1),
            (("windows.ndjson", 0, "start_ms"), 1),
            (("windows.ndjson", 0, "inflight_start"), 1),
            (("windows.ndjson", 0, "inflight_end"), 1),
            (("windows.ndjson", 0, "counts", "replies"), 9),
            (("windows.ndjson", 0, "histogram", "p50_us"), 0),
            (("windows.ndjson", 0, "completed_phase_counts"), {"steady": 9}),
            (("run.json", "phases", 0, "seconds"), True),
            (("run.json", "limits", "aggregate_bytes"), 1 << 32),
            (("run.json", "identity", "binary_sha256"), "bad"),
        ]
        for path, value in mutations:
            with self.subTest(path=path):
                bundle = fixture()
                set_path(bundle, path, value)
                with self.assertRaises(e.access.CollectionError):
                    self.verify_bundle(bundle)

    def test_missing_duplicate_partial_and_oversized_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = fixture()
            for name in bundle:
                save(root, bundle)
                (root / name).unlink()
                with self.subTest(missing=name), self.assertRaises(OSError):
                    verifier.verify(root)
            for name, content in [("summary.json", '{"format":1,"format":1}'),
                                  ("summary.json", "[" * 33 + "0" + "]" * 33),
                                  ("summary.json", "{"), ("summary.json", "NaN"),
                                  ("run.json", " " * 262145),
                                  ("windows.ndjson", " " * 16385 + "\n")]:
                save(root, bundle)
                (root / name).write_text(content)
                with self.subTest(name=name, content=content[:40]), self.assertRaises((e.access.CollectionError, ValueError)):
                    verifier.verify(root)
            save(root, bundle)
            path = root / "windows.ndjson"
            line = path.read_text()
            for content in (line.rstrip("\n"), line + line, ""):
                path.write_text(content)
                with self.assertRaises(e.access.CollectionError):
                    verifier.verify(root)

    def test_no_follow_and_special_files_never_block(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "evidence"
            root.mkdir()
            bundle = fixture()
            save(root, bundle)
            (parent / "linked").symlink_to(root, target_is_directory=True)
            with self.assertRaises(OSError):
                verifier.verify(parent / "linked")
            for name in bundle:
                for special in ("symlink", "fifo"):
                    save(root, bundle)
                    path = root / name
                    path.unlink()
                    if special == "symlink":
                        path.symlink_to(root / "nonexistent")
                    else:
                        os.mkfifo(path)
                    with self.subTest(name=name, special=special), self.assertRaises((OSError, e.access.CollectionError)):
                        verifier.verify(root)
                    path.unlink()

    def test_cli_exit_codes_are_distinct_and_invalid_errors_are_sanitized(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = fixture()
            save(root, bundle)
            command = [sys.executable, str(SCRIPT), "--directory", str(root)]
            result = subprocess.run(command, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)["driver_passed"])
            bundle["summary.json"].update(driver_passed=False, completed=False, failure="cancelled")
            save(root, bundle)
            result = subprocess.run(command, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertTrue(json.loads(result.stdout)["evidence_consistent"])
            self.assertFalse(json.loads(result.stdout)["driver_passed"])
            (root / "summary.json").write_text('{"secret":"never print this"')
            result = subprocess.run(command, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 1)
            self.assertFalse(json.loads(result.stdout)["evidence_consistent"])
            self.assertNotIn(b"secret", result.stdout + result.stderr)

    def test_native_utf8_text_byte_limits_and_bounded_output(self):
        with self.assertRaises(e.access.CollectionError):
            e.text("é" * 513)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = fixture()
            checks = ["é" * 512] * 32
            bundle["run.json"]["external_checks"] = checks
            bundle["summary.json"]["external_checks_unverified"] = checks
            save(root, bundle)
            # Match native serde_json's UTF-8 representation rather than test default ASCII escapes.
            for name in ("run.json", "summary.json"):
                (root / name).write_text(json.dumps(bundle[name], ensure_ascii=False))
            result = subprocess.run([sys.executable, str(SCRIPT), "--directory", str(root)],
                                    capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertLessEqual(len(result.stdout), 65536)
            self.assertEqual(json.loads(result.stdout)["external_checks_unverified"], checks)

    def test_deterministic_bounded_mutations_have_only_supported_failures(self):
        rng = random.Random(32)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = fixture()
            save(root, bundle)
            originals = {name: (root / name).read_bytes() for name in bundle}
            for _ in range(160):
                name = rng.choice(list(originals))
                data = bytearray(originals[name])
                position = rng.randrange(len(data))
                data[position] = rng.randrange(256)
                (root / name).write_bytes(data)
                try:
                    verifier.verify(root)
                except (e.access.CollectionError, OSError, ValueError, RecursionError):
                    pass
                finally:
                    (root / name).write_bytes(originals[name])


if __name__ == "__main__":
    unittest.main()
