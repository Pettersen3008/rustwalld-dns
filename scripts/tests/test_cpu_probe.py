import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("cpu_probe", Path(__file__).resolve().parents[1] / "cpu-probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def output(*rows):
    return "\t".join(probe.FIELDS) + "\n" + "\n".join("\t".join(map(str, row)) for row in rows) + "\n"


class CpuProbe(unittest.TestCase):
    def test_known_tick_accounting_and_summary(self):
        text = output(("cache", 1, 1000000, 90, 10, 100, 1200000000, 0))
        rows = probe.parse_results(text, 1000000, 1, ["cache"], 100)
        self.assertEqual(rows[0]["cpu_ns_per_query"], 1000)
        self.assertEqual(rows[0]["rounding_allowance_ns_per_query"], 20)
        self.assertEqual(probe.summarize(rows)["cache"]["median_cpu_ns_per_query"], 1000)

    def test_short_or_mixed_precision_never_claims_zero_cpu(self):
        text = output(("cache", 1, 10000, 0, 0, 100, 10000000, 0),
                      ("cache", 2, 10000, 20, 0, 100, 210000000, 0))
        rows = probe.parse_results(text, 10000, 2, ["cache"], 100)
        self.assertIsNone(rows[0]["cpu_ns_per_query"])
        self.assertIsNone(probe.summarize(rows)["cache"]["median_cpu_ns_per_query"])

    def test_rejects_missing_duplicate_unknown_or_inconsistent_rows(self):
        valid = ("cache", 1, 1000000, 90, 10, 100, 1200000000, 0)
        bad = [output(), output(valid, valid), output(("wrong", *valid[1:])),
               output((valid[0], 2, *valid[2:])), output((valid[0], valid[1], 1, *valid[3:])),
               output((*valid[:5], 1000, *valid[6:])), output((*valid[:-1], 1)),
               output((*valid[:3], -1, *valid[4:])), output((*valid[:6], 1, *valid[7:])),
               output(valid) + "cache\t1\n", "unexpected\n", "x" * 65537]
        for text in bad:
            with self.subTest(text=text[:80]), self.assertRaises(ValueError):
                probe.parse_results(text, 1000000, 1, ["cache"], 100)

    def test_median_does_not_select_best_batch(self):
        text = output(("cache", 1, 1000000, 90, 0, 100, 1100000000, 0),
                      ("cache", 2, 1000000, 110, 0, 100, 1200000000, 0),
                      ("cache", 3, 1000000, 100, 0, 100, 1150000000, 0))
        result = probe.summarize(probe.parse_results(text, 1000000, 3, ["cache"], 100))
        self.assertEqual(result["cache"]["median_cpu_ns_per_query"], 1000)


if __name__ == "__main__":
    unittest.main()
