import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("comparison", Path(__file__).resolve().parents[1] / "compare-appliances.py")
comparison = importlib.util.module_from_spec(spec)
spec.loader.exec_module(comparison)


def row(scenario="cache", upstream=0):
    return {"scenario": scenario, "transport": "udp", "queries": 1000,
            "concurrency": 4, "passed": True, "elapsed_ns": 10000000,
            "upstream_requests": upstream, "tcp_reconnects": 0, "exchange_errors": 0, "first_error": None,
            "histogram": {"replies": 1000, "incorrect": 0, "timeouts": 0,
                          "latencies_clipped": 0, "p50_us": 10, "p95_us": 20,
                          "p99_us": 30, "p999_us": 40}}


class Comparison(unittest.TestCase):
    def test_paced_history_cannot_hide_drops_failures_pending_or_missing_rows(self):
        metrics={"rustwalld_requests_total": 40000, "rustwalld_events_dropped_total": 0,
                 "rustwalld_history_write_failures_total": 0, "rustwalld_history_events_total": 40000}
        evidence={"metrics":metrics,"retained_queries":40000}
        comparison.validate_paced_history(evidence)
        for key,value in (("rustwalld_events_dropped_total",1),("rustwalld_history_write_failures_total",1),
                          ("rustwalld_history_events_total",39999),("rustwalld_requests_total",0)):
            changed={"metrics":dict(metrics,**{key:value}),"retained_queries":40000}
            with self.subTest(key=key), self.assertRaises(ValueError):
                comparison.validate_paced_history(changed)
        with self.assertRaises(ValueError):
            comparison.validate_paced_history({"metrics":metrics,"retained_queries":39999})

    def test_correct_rows_preserve_counts_and_observed_coalescing(self):
        for scenario, upstream in (("cache", 0), ("cold", 1000), ("coalescing", 1), ("coalescing", 1000)):
            report = row(scenario, upstream)
            self.assertIs(comparison.validate_report(report, scenario, "udp", 1000, 4), report)

    def test_incorrect_incomplete_or_mismatched_reports_are_rejected(self):
        changes = (("passed", False), ("scenario", "wrong"), ("transport", "tcp"),
                   ("queries", 999), ("concurrency", 5), ("elapsed_ns", 0),
                   ("upstream_requests", 1), ("tcp_reconnects", 1), ("tcp_reconnects", -1),
                   ("exchange_errors", 1), ("first_error", "connection closed"))
        for key, value in changes:
            report = row()
            report[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                comparison.validate_report(report, "cache", "udp", 1000, 4)
        for key in ("incorrect", "timeouts", "latencies_clipped"):
            report = row()
            report["histogram"][key] = 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                comparison.validate_report(report, "cache", "udp", 1000, 4)

    def test_missing_duplicate_request_accounting_and_bad_quantiles_rejected(self):
        for scenario, upstream in (("cold", 999), ("coalescing", 0), ("coalescing", 1001)):
            with self.assertRaises(ValueError):
                comparison.validate_report(row(scenario,upstream), scenario, "udp", 1000, 4)
        for key,value in (("replies",999),("p99_us",-1),("p50_us",50)):
            report=row()
            report["histogram"][key]=value
            with self.assertRaises(ValueError):
                comparison.validate_report(report,"cache","udp",1000,4)

    def test_cpu_topology_ranges_are_not_mistaken_for_independent_cores(self):
        self.assertEqual(comparison.cpu_list("0-3,8,10-11\n"), {0,1,2,3,8,10,11})
        for value in ("", "-1", "3-2", "1-2-3", "65536", "a"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                comparison.cpu_list(value)
