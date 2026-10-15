"""Strict native soak-output shapes and derivable offline invariants."""
import importlib.util
import ipaddress
import json
from pathlib import Path
import re

_spec = importlib.util.spec_from_file_location("soak_collector", Path(__file__).with_name("soak-collect.py"))
access = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(access)
require, u64 = access.require, access.u64
COUNT_KEYS = "offered sent replies timeouts errors wrong skipped cancelled".split()
QUANTILE_KEYS = "replies timeouts incorrect latencies_clipped max_us p50_us p95_us p99_us p999_us".split()
PRECISION = "exact us through 1 ms, 100 us upper bounds thereafter; 2 s cap; 21001 bins"


def shape(value, keys):
    require(type(value) is dict and set(value) == set(keys), "unsupported object fields")
    return value


def array(value, low, high):
    require(type(value) is list and low <= len(value) <= high, "array cardinality")
    return value


def number(value, low=0, high=(1 << 64) - 1):
    value = u64(value)
    require(low <= value <= high, "numeric bound")
    return value


def boolean(value):
    require(type(value) is bool, "boolean required")
    return value


def text(value, cap=1024):
    require(type(value) is str and 1 <= len(value.encode("utf-8")) <= cap
            and all(ord(c) >= 32 and ord(c) != 127 for c in value), "invalid bounded text")
    return value


def identifier(value):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value), "invalid identity")
    return value


def unique(values, key):
    names = [identifier(value[key]) for value in values]
    require(len(names) == len(set(names)), "duplicate identity")
    return names


def parse(text_value):
    # Bound nesting before json.loads, including implementations with iterative parsing.
    depth, quoted, escaped = 0, False, False
    for char in text_value:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            require(depth <= 32, "JSON nesting limit")
        elif char in "]}":
            depth -= 1
    def bad_constant(_value):
        raise access.CollectionError("invalid JSON constant")
    return json.loads(text_value, object_pairs_hook=access.unique_object, parse_constant=bad_constant)


def counts(value):
    shape(value, COUNT_KEYS)
    for n in value.values():
        u64(n)
    require(value["wrong"] <= value["replies"], "wrong exceeds replies")
    return value


def zeros():
    return dict.fromkeys(COUNT_KEYS, 0)


def add(left, right):
    return {name: u64(left[name] + right[name]) for name in COUNT_KEYS}


def reconciled(value):
    return (value["offered"] == u64(value["sent"] + value["skipped"])
            and value["sent"] == u64(sum(value[k] for k in ("replies", "timeouts", "errors", "cancelled"))))


def origins(value, phases, completed):
    require(type(value) is dict and len(value) <= 64 and set(value) <= set(phases), "completion origins")
    require(u64(sum(u64(n) for n in value.values())) == completed, "completion origin sum")
    return value


def quantiles(value, count):
    shape(value, QUANTILE_KEYS)
    for n in value.values():
        u64(n)
    require((value["replies"], value["timeouts"], value["incorrect"])
            == (count["replies"], count["timeouts"], count["wrong"]), "histogram counts")
    require(value["latencies_clipped"] <= count["replies"], "clipped count")
    q = [value[k] for k in ("p50_us", "p95_us", "p99_us", "p999_us")]
    require(all(us <= 1000 or (us - 1000) % 100 == 0 for us in q), "unrepresentable quantile bucket")
    maximum = min(value["max_us"], 2000000)
    ceiling = maximum if maximum <= 1000 else 1000 + ((maximum - 1000 + 99) // 100) * 100
    require(q == sorted(q) and q[-1] <= ceiling, "quantile range")
    if count["replies"] == 0:
        require(value["max_us"] == 0 and q == [0] * 4 and value["latencies_clipped"] == 0,
                "empty histogram values")
    require((value["max_us"] > 2000000) == (value["latencies_clipped"] > 0), "clipping/max mismatch")


def bucket(microseconds):
    microseconds = min(microseconds, 2000000)
    return microseconds if microseconds <= 1000 else 1000 + (microseconds - 1000 + 99) // 100


def histogram(value, count, report):
    shape(value, "bins replies timeouts incorrect clipped max_us".split())
    bins = array(value["bins"], 21001, 21001)
    for n in bins:
        u64(n)
    require(u64(sum(bins)) == count["replies"] and not any(bins[20991:]), "histogram bin sum/tail")
    quantiles(report, count)
    for raw, shown in [("replies", "replies"), ("timeouts", "timeouts"), ("incorrect", "incorrect"),
                       ("clipped", "latencies_clipped"), ("max_us", "max_us")]:
        require(u64(value[raw]) == report[shown], "raw histogram scalar mismatch")
    require(value["clipped"] <= bins[20990], "clipped bucket count")
    if count["replies"]:
        maximum = min(value["max_us"], 2000000)
        bucket = maximum if maximum <= 1000 else 1000 + (maximum - 1000 + 99) // 100
        require(max(i for i, n in enumerate(bins) if n) == bucket, "maximum bucket mismatch")
    for key, percentile in [("p50_us", 500), ("p95_us", 950), ("p99_us", 990), ("p999_us", 999)]:
        expected, cumulative = 0, 0
        if count["replies"]:
            rank = (count["replies"] * percentile + 999) // 1000
            for i, n in enumerate(bins):
                cumulative += n
                if cumulative >= rank:
                    expected = i if i <= 1000 else 1000 + (i - 1000) * 100
                    break
        require(report[key] == expected, "aggregate quantile mismatch")


def run_record(value):
    shape(value, "format run_id seed mode authority identity collector limits clients lanes phases external_checks".split())
    require(number(value["format"]) == 1 and value["mode"] in ("qualification", "soak"), "unsupported run format")
    identifier(value["run_id"])
    u64(value["seed"])
    shape(value["authority"], "instruction window stop_owner allowed_actions reversal".split())
    for item in value["authority"].values():
        text(item)
    identity = shape(value["identity"], ("revision source_sha256 binary_sha256 dataset_sha256 "
                     "appliance_config_sha256 controller_plan_sha256 appliance_limits platform topology clock_check workload_basis").split())
    for key in ("revision", "source_sha256", "binary_sha256", "dataset_sha256", "appliance_config_sha256", "controller_plan_sha256"):
        require(type(identity[key]) is str and re.fullmatch(r"[a-fA-F0-9]{%d}" % (40 if key == "revision" else 64), identity[key]),
                "invalid recorded hash")
    for key in ("platform", "topology", "clock_check", "workload_basis"):
        text(identity[key])
    limits = shape(identity["appliance_limits"], "raw_cache decision_cache inflight udp_tasks upstream_waiters tcp_connections event_queue history".split())
    for item in limits.values():
        number(item, 1, (1 << 32) - 1)
    collector = shape(value["collector"], ["path", "target_id", "max_age_ms"])
    identifier(collector["target_id"])
    require(Path(text(collector["path"], 4096)).is_absolute(), "collector path shape")
    number(collector["max_age_ms"], 1000, 3000)
    limits = shape(value["limits"], "outstanding latency_us resources artifact_bytes aggregate_bytes window_bytes".split())
    number(limits["outstanding"], 1, 256)
    number(limits["latency_us"], 1, 2000000)
    for item in array(limits["resources"], 6, 6):
        number(item, 1)
    number(limits["aggregate_bytes"], 262144, 16777216)
    number(limits["artifact_bytes"], limits["aggregate_bytes"] + 524288, 134217728)
    number(limits["window_bytes"], 1024, 16384)
    for client in array(value["clients"], 1, 16):
        shape(client, ["id", "bind"])
        text(client["bind"], 64)
        ipaddress.ip_address(client["bind"])
    unique(value["clients"], "id")
    for lane in array(value["lanes"], 1, 32):
        shape(lane, "id client endpoint transport weight responses ttl_floor tcp_fallback fresh".split())
        number(lane["client"], 0, len(value["clients"]) - 1)
        text(lane["endpoint"], 128)
        require(lane["transport"] in ("udp", "tcp"), "unsupported transport")
        number(lane["weight"], 1, 65535)
        number(lane["ttl_floor"], 0, (1 << 32) - 1)
        boolean(lane["tcp_fallback"])
        boolean(lane["fresh"])
        for reference in array(lane["responses"], 1, 4):
            require(type(reference) is str and 24 <= len(reference) <= 8192 and len(reference) % 2 == 0
                    and re.fullmatch(r"[A-Fa-f0-9]+", reference), "reference shape (not DNS validation)")
    unique(value["lanes"], "id")
    seconds, windows, start = 0, 0, 0
    phases = {}
    for phase in array(value["phases"], 1, 64):
        shape(phase, "id seconds qps deadline_ms max_lag_ms accepted generations allow_timeouts".split())
        identifier(phase["id"])
        require(phase["id"] not in phases, "duplicate phase")
        duration = number(phase["seconds"], 1, 259200)
        number(phase["qps"], 1, 100000)
        number(phase["deadline_ms"], 1, 2000)
        number(phase["max_lag_ms"], 1, 1000)
        require(limits["latency_us"] <= phase["deadline_ms"] * 1000, "latency/deadline mismatch")
        boolean(phase["allow_timeouts"])
        for index in array(phase["accepted"], 1, 4):
            number(index, 0, min(len(lane["responses"]) for lane in value["lanes"]) - 1)
        for generation in array(phase["generations"], 1, 32):
            u64(generation)
        phases[phase["id"]] = (phase, start, start + duration * 1000)
        start += duration * 1000
        seconds += duration
        windows += (duration + 59) // 60
    require(seconds <= (900 if value["mode"] == "qualification" else 259200) and windows <= 4320,
            "run duration/window bound")
    for item in array(value["external_checks"], 1, 32):
        text(item)
    return phases


def counters(value, names=None):
    require(type(value) is dict and len(value) <= 16, "counter map cardinality")
    for key, item in value.items():
        require(re.fullmatch(r"[A-Za-z0-9_]{1,64}", key), "counter name")
        u64(item)
    if names is not None:
        require(set(value) <= names, "counter schema mismatch")


def process(value):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9_:-]{1,64}", value), "process identity")


def gauges(value, run):
    for observed, limit in zip(array(value, 6, 6), run["limits"]["resources"]):
        require(u64(observed) <= limit, "resource budget exceeded")


def resource_summary(value, run, generations, sample_generations=None):
    shape(value, "samples first last min max counter_deltas counter_resets resets".split())
    samples = number(value["samples"], 0, 1000000)
    resets = array(value["resets"], 0, 16)
    require(len(resets) <= samples, "reset events exceed new observations")
    u64(value["counter_resets"])
    counters(value["counter_deltas"])
    if not samples:
        require(all(value[k] is None for k in ("first", "last", "min", "max"))
                and not value["counter_deltas"] and not resets and value["counter_resets"] == 0,
                "empty resources mismatch")
        return
    for snapshot in (value["first"], value["last"]):
        shape(snapshot, "run_id target_id process_id sequence unix_ms generation resources counters".split())
        require(snapshot["run_id"] == run["run_id"] and snapshot["target_id"] == run["collector"]["target_id"],
                "sample identity mismatch")
        process(snapshot["process_id"])
        u64(snapshot["sequence"])
        u64(snapshot["unix_ms"])
        require(u64(snapshot["generation"]) in (generations if sample_generations is None else sample_generations),
                "sample generation mismatch")
        gauges(snapshot["resources"], run)
        counters(snapshot["counters"])
        require(snapshot["counters"], "empty sample counters")
    first, last = value["first"], value["last"]
    require(first["sequence"] <= last["sequence"] and first["unix_ms"] <= last["unix_ms"]
            and set(first["counters"]) == set(last["counters"]), "sample continuity")
    require(samples <= last["sequence"] - first["sequence"] + 1, "sample/sequence cardinality")
    if samples == 1:
        require(first == last, "single sample changed")
    else:
        require(first["sequence"] < last["sequence"], "sample sequence reused")
    names = set(first["counters"])
    counters(value["counter_deltas"], names)
    gauges(value["min"], run)
    gauges(value["max"], run)
    require(all(lo <= a <= hi and lo <= b <= hi for lo, a, b, hi in
                zip(value["min"], first["resources"], last["resources"], value["max"])), "resource extrema")
    if samples == 1:
        require(value["min"] == value["max"] == first["resources"], "single sample extrema")
    for reset in resets:
        shape(reset, "from_process to_process from_generation to_generation counters".split())
        process(reset["from_process"])
        process(reset["to_process"])
        require(u64(reset["from_generation"]) in generations and u64(reset["to_generation"]) in generations,
                "reset generation")
        affected = array(reset["counters"], 1, 16)
        require(all(type(name) is str for name in affected)
                and len(set(affected)) == len(affected) and set(affected) <= names, "reset counter schema")
    require(sum(len(r["counters"]) for r in resets) == value["counter_resets"], "reset accounting")


def global_resource_semantics(value):
    samples = value["samples"]
    require(len(value["resets"]) <= max(samples - 1, 0), "global reset events exceed transitions")
    if samples == 1:
        require(not value["counter_deltas"] and not value["resets"] and value["counter_resets"] == 0,
                "initial sample cannot establish counter changes")
    elif samples >= 2:
        first, last = value["first"], value["last"]
        identity_changed = (first["process_id"], first["generation"]) != (last["process_id"], last["generation"])
        if samples == 2:
            affected = sorted(name for name in first["counters"]
                              if identity_changed or last["counters"][name] < first["counters"][name])
            expected_deltas = {name: last["counters"][name] - before for name, before in first["counters"].items()
                               if name not in affected}
            expected_resets = ([dict(from_process=first["process_id"], to_process=last["process_id"],
                                    from_generation=first["generation"], to_generation=last["generation"], counters=affected)]
                               if affected else [])
            require(value["counter_deltas"] == expected_deltas and value["counter_resets"] == len(affected)
                    and value["resets"] == expected_resets, "global two-sample counter transition mismatch")
            require(value["min"] == list(map(min, first["resources"], last["resources"]))
                    and value["max"] == list(map(max, first["resources"], last["resources"])), "global two-sample extrema mismatch")
        elif value["counter_resets"] == 0:
            require(not identity_changed, "global identity changed without reset")
            expected_deltas = {name: u64(last["counters"][name] - before) for name, before in first["counters"].items()}
            require(value["counter_deltas"] == expected_deltas, "global no-reset counter delta mismatch")
