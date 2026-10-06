#!/usr/bin/env python3
"""Correctness-gated, network-isolated comparison of pinned local DNS appliances."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import shutil
import sqlite3
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
PRODUCTS = ("rustwalld", "pihole", "adguard")
SCENARIOS = ("blocked", "suffix", "cache", "aaaa", "cname", "negative", "cold", "coalescing")

def cpu_list(value):
    result = set()
    for part in value.strip().split(","):
        ends = part.split("-")
        if len(ends) not in (1, 2):
            raise ValueError("invalid CPU range")
        first = int(ends[0])
        last = int(ends[-1])
        if not 0 <= first <= last <= 65535:
            raise ValueError("invalid CPU bounds")
        result.update(range(first, last + 1))
    return result


def command(*args, timeout=180):
    try:
        return subprocess.check_output(args, cwd=ROOT, text=True, stderr=subprocess.STDOUT, timeout=timeout).strip()
    except subprocess.CalledProcessError as error:
        raise RuntimeError(f"command failed: {args[0]}: {error.output[-8192:]}") from error


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_report(row, scenario, transport, iterations, concurrency):
    if (row.get("scenario") != scenario or row.get("transport") != transport
            or row.get("queries") != iterations or row.get("concurrency") != concurrency
            or row.get("passed") is not True):
        raise ValueError("scenario/transport/count/gate mismatch")
    histogram = row["histogram"]
    if row["exchange_errors"] != 0 or row["first_error"] is not None:
        raise ValueError("DNS exchange failed")
    if histogram["replies"] != iterations or any(histogram[key] != 0 for key in ("incorrect", "timeouts", "latencies_clipped")):
        raise ValueError("DNS correctness gate failed")
    if not 0 < row["elapsed_ns"] < 300_000_000_000:
        raise ValueError("invalid measured interval")
    if not 0 <= row["tcp_reconnects"] <= iterations or (transport == "udp" and row["tcp_reconnects"] != 0):
        raise ValueError("invalid TCP reconnection accounting")
    if scenario == "cold":
        valid = row["upstream_requests"] == iterations
    elif scenario == "coalescing":
        valid = 1 <= row["upstream_requests"] <= iterations
    else:
        valid = row["upstream_requests"] == 0
    if not valid:
        raise ValueError("unexpected upstream requests")
    if any(histogram[key] < 0 for key in ("p50_us", "p95_us", "p99_us", "p999_us")):
        raise ValueError("negative quantile")
    if not histogram["p50_us"] <= histogram["p95_us"] <= histogram["p99_us"] <= histogram["p999_us"]:
        raise ValueError("unordered quantiles")
    return row


def fixtures(directory, rules, schema):
    domains = [f"d{i}.blocked.bench.test" for i in range(rules)]
    canonical = "\n".join(domains) + "\n"
    (directory / "domains.txt").write_text(canonical)
    (directory / "rules-rust.txt").write_text("\n".join("=" + name for name in domains) + "\nsuffix.bench.test\n")
    (directory / "allow-rust.txt").write_text("=allowed.suffix.bench.test\n")
    (directory / "rustwalld.toml").write_text("""
dns_listen = "127.0.0.1:5353"
api_listen = "127.0.0.1:8080"
database = "/work/state.sqlite"
dns_cache_entries = 4096
decision_cache_entries = 16384
max_inflight = 128
max_udp_queries = 128
max_tcp_connections = 64
history_rows = 100000
filter_files = [
 {policy="default",name="fixture",action="block",path="/work/rules-rust.txt"},
 {policy="default",name="allow",action="allow",path="/work/allow-rust.txt"},
]
[policy]
default_policy = "default"
bindings = []
allowed_clients = ["127.0.0.1/32"]
assertions = []
[[policy.policies]]
name = "default"
upstream = "default"
lists = []
rewrites = []
[[policy.upstreams]]
name = "default"
addresses = ["127.0.0.1:1053"]
timeout_ms = 2000
""")
    work = directory / "adguard-work"
    filters = work / "data/filters"
    filters.mkdir(parents=True)
    native = "\n".join("|" + name + "^" for name in domains) + "\n"
    (filters / "1.txt").write_text(native)
    (work / "fixture.txt").write_text(native)
    config = {
        "schema_version": 34, "http": {"address": "127.0.0.1:8080"},
        "dns": {"bind_hosts": ["127.0.0.1"], "port": 5353,
                "upstream_dns": ["127.0.0.1:1053"], "upstream_mode": "load_balance",
                "bootstrap_dns": [], "fallback_dns": [], "ratelimit": 0,
                "cache_enabled": True, "cache_size": 4194304,
                "cache_ttl_min": 0, "cache_ttl_max": 0, "cache_optimistic": False,
                "use_private_ptr_resolvers": False, "local_ptr_upstreams": [],
                "upstream_timeout": "2s"},
        "filtering": {"protection_enabled": True, "filtering_enabled": True,
                      "blocking_mode": "nxdomain", "filters_update_interval": 0,
                      "blocked_response_ttl": 2, "rewrites": []},
        "filters": [{"enabled": True, "url": "/opt/adguardhome/work/fixture.txt", "name": "fixture", "id": 1}],
        "user_rules": ["||suffix.bench.test^", "@@|allowed.suffix.bench.test^"],
        "querylog": {"enabled": True, "file_enabled": True, "interval": "24h", "size_memory": 1000},
        "statistics": {"enabled": True, "interval": "24h"},
    }
    (directory / "AdGuardHome.yaml").write_text(json.dumps(config, indent=2) + "\n")
    database = directory / "gravity.db"
    with sqlite3.connect(database) as connection:
        connection.executescript(schema)
        connection.execute("INSERT INTO adlist(id,address,number,status) VALUES(1,?, ?,1)", ("http://127.0.0.1:1055/unused-list", rules))
        connection.executemany("INSERT INTO gravity(domain,adlist_id) VALUES(?,1)", ((name,) for name in domains))
        connection.execute("CREATE INDEX idx_gravity ON gravity(domain,adlist_id)")
        connection.execute("INSERT INTO info(property,value) VALUES('updated',?)", (str(int(time.time())),))
        connection.execute("INSERT INTO info(property,value) VALUES('gravity_count',?)", (str(rules),))
        connection.execute("INSERT INTO info(property,value) VALUES('antigravity_count','0')")
        connection.execute("INSERT INTO domainlist(type,domain) VALUES(3,?)", (r"(^|\.)suffix\.bench\.test$",))
        connection.execute("INSERT INTO domainlist(type,domain) VALUES(0,'allowed.suffix.bench.test')")
    return hashlib.sha256(canonical.encode()).hexdigest()


def counters(directory):
    cpu = dict(line.split() for line in (directory / "cpu.stat").read_text().splitlines())
    return {key: int(cpu[key]) for key in ("usage_usec", "nr_throttled", "throttled_usec")} | {
        "memory_current_bytes": int((directory / "memory.current").read_text()),
        "memory_peak_bytes": int((directory / "memory.peak").read_text()),
    }


def cgroup(container):
    pid = int(command("docker", "inspect", "--format", "{{.State.Pid}}", container))
    value = Path(f"/proc/{pid}/cgroup").read_text().strip()
    if not value.startswith("0::/") or "\n" in value:
        raise ValueError("comparison requires readable host cgroup v2")
    path = Path("/sys/fs/cgroup") / value.removeprefix("0::/")
    counters(path)
    return path

def rss(pid):
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) * 1024
    raise ValueError("DNS process RSS unavailable")

def dns_pid(container, product):
    expected = {"rustwalld": "daemon", "pihole": "pihole-FTL", "adguard": "AdGuardHome"}[product]
    rows = command("docker", "top", container, "-eo", "pid,comm").splitlines()[1:]
    found = [int(line.split()[0]) for line in rows if line.split()[1] == expected]
    if len(found) != 1:
        raise ValueError("expected exactly one DNS process")
    rss(found[0])
    return found[0]


def history_evidence(container, namespace, product, image, directory, name, resources):
    """Observe history after DNS timing; stop writers before copying durable files."""
    evidence = {}
    if product == "rustwalld":
        resources.append(name)
        text = command("docker", "run", "--rm", "--name", name, "--network", "container:"+namespace,
                       "--entrypoint", "/usr/bin/curl", image, "--fail", "--silent", "--max-time", "5",
                       "http://127.0.0.1:8080/metrics", timeout=30)
        evidence["metrics"] = {line.split()[0]: int(line.split()[1]) for line in text.splitlines()
                               if not line.startswith("#") and line.split()[0] in
                               ("rustwalld_requests_total", "rustwalld_events_dropped_total", "rustwalld_history_events_total", "rustwalld_history_write_failures_total")}
    command("docker", "stop", "--time", "15", container, timeout=30)
    local = directory / (name + ".history")
    if product in ("rustwalld", "pihole"):
        source = "/work/state.sqlite" if product == "rustwalld" else "/etc/pihole/pihole-FTL.db"
        command("docker", "cp", container+":"+source, str(local))
        # Writers have stopped; preserve a remaining WAL if the native shutdown kept it.
        for suffix in ("-wal", "-shm"):
            try:
                command("docker", "cp", container+":"+source+suffix, str(local)+suffix)
            except RuntimeError:
                pass
        with sqlite3.connect(local) as connection:
            evidence["retained_queries"] = connection.execute("SELECT COUNT(*) FROM queries").fetchone()[0]
    else:
        command("docker", "cp", container+":/opt/adguardhome/work/data/querylog.json", str(local))
        with local.open() as stream:
            first = stream.readline()
            json.loads(first)
            evidence["retained_queries"] = 1 + sum(1 for line in stream if line.strip())
    evidence["history_file_bytes"] = local.stat().st_size
    return evidence


def validate_paced_history(evidence):
    metrics = evidence["metrics"]
    requests = metrics["rustwalld_requests_total"]
    if (requests <= 0 or metrics["rustwalld_events_dropped_total"] != 0
            or metrics["rustwalld_history_write_failures_total"] != 0
            or metrics["rustwalld_history_events_total"] != requests
            or evidence["retained_queries"] != min(requests,100000)):
        raise ValueError("paced history delivery gate failed")


def benchmark(driver_image, namespace, product_group, pid, cpu, scenario, transport, iterations, concurrency, rules, nonce, rate, name, resources):
    arguments = ["docker", "run", "--rm", "-i", "--name", name, "--pull", "never",
                 "--network", "container:" + namespace, "--read-only", "--cpuset-cpus", str(cpu),
                 "--cpus", "1", "--memory", "512m", driver_image, "run",
                 "--scenario", scenario, "--transport", transport,
                 "--iterations", str(iterations), "--concurrency", str(concurrency),
                 "--rules", str(rules), "--nonce", str(nonce), "--queries-per-second", str(rate)]
    resources.append(name)
    process = subprocess.Popen(arguments, cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            if not selector.select(90):
                raise TimeoutError("driver READY deadline exceeded")
            ready = process.stdout.readline(65537)
            if ready != "READY\n":
                _, errors = process.communicate(timeout=30)
                raise ValueError(f"driver failed before READY: {ready[-4000:]} {errors[-4000:]}")
        rss_before = rss(pid)
        before = counters(product_group)
        started = time.monotonic_ns()
        process.stdin.write("GO\n")
        process.stdin.flush()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            if not selector.select(300):
                raise TimeoutError("driver result deadline exceeded")
            output = process.stdout.readline(65537)
        ended = time.monotonic_ns()
        after = counters(product_group)
        rss_after = rss(pid)
        trailing, errors = process.communicate(timeout=30)
        if process.returncode != 0:
            raise ValueError(f"driver rejected workload: {output[-4000:]} {errors[-4000:]}")
        if len(output) > 65536 or trailing.strip():
            raise ValueError("oversized or trailing driver report")
        row = validate_report(json.loads(output), scenario, transport, iterations, concurrency)
        if row.get("queries_per_second_limit") != rate:
            raise ValueError("driver pacing identity mismatch")
        deltas = {key: after[key] - before[key] for key in ("usage_usec", "nr_throttled", "throttled_usec")}
        if any(value < 0 for value in deltas.values()):
            raise ValueError("cgroup counters moved backwards")
        row.update({"cgroup_before": before, "cgroup_after": after, "cgroup_delta": deltas,
                    "controller_interval_ns": ended - started,
                    "dns_process_rss_before_bytes": rss_before, "dns_process_rss_after_bytes": rss_after,
                    "appliance_cpu_ns_per_query": deltas["usage_usec"] * 1000 / iterations,
                    "achieved_queries_per_second": iterations * 1e9 / row["elapsed_ns"]})
        return row
    finally:
        if process.poll() is None:
            command("docker", "rm", "-f", name, timeout=20)
            process.kill()
        process.communicate(timeout=20)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=100000)
    parser.add_argument("--rules", type=int, default=100000)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--queries-per-second", type=int, default=0, help="optional paced warm workload, zero is unpaced; cold/burst rows remain unpaced")
    parser.add_argument("--server-cpu", type=int, default=2)
    parser.add_argument("--driver-cpu", type=int, default=4)
    parser.add_argument("--upstream-cpu", type=int, default=6)
    parser.add_argument("--shared-memory-mib", type=int, choices=(64,256), default=256, help="appliance /dev/shm ceiling within its 512 MiB cgroup")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--binary", type=Path, default=ROOT / "target/release/rustwalld-dns", help="trusted prebuilt daemon for matched comparisons; requires --skip-build")
    parser.add_argument("--inject-wrong-answer", action="store_true")
    parser.add_argument("--products", nargs="+", choices=PRODUCTS, default=list(PRODUCTS))
    parser.add_argument("--scenarios", nargs="+", choices=SCENARIOS, default=list(SCENARIOS))
    parser.add_argument("--transports", nargs="+", choices=("udp","tcp"), default=["udp","tcp"])
    args = parser.parse_args()
    if args.binary != ROOT / "target/release/rustwalld-dns" and not args.skip_build:
        parser.error("--binary requires --skip-build")
    if any(len(values) != len(set(values)) for values in (args.products,args.scenarios,args.transports)):
        parser.error("duplicate products/scenarios/transports are not admitted")
    if args.queries_per_second != 0 and not 100 <= args.queries_per_second <= 100000:
        parser.error("query rate must be zero or 100..100000")
    if args.queries_per_second and args.iterations / args.queries_per_second >= 270:
        parser.error("paced warm workload must fit the result deadline")
    if platform.system() != "Linux" or not 1000 <= args.iterations <= 1000000 or not 1 <= args.rules <= 1000000 or not 1 <= args.rounds <= 5 or not 1 <= args.concurrency <= 64:
        parser.error("requires Linux, iterations 1000..1000000, rules 1..1000000, rounds 1..5, concurrency 1..64")
    cpus = (args.server_cpu, args.driver_cpu, args.upstream_cpu)
    if len(set(cpus)) != 3 or not set(cpus) <= os.sched_getaffinity(0):
        parser.error("three distinct admitted CPUs are required")
    siblings = [cpu_list(Path(f"/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list").read_text()) for cpu in cpus]
    if any(b in siblings[i] for i,a in enumerate(cpus) for b in cpus if a != b):
        parser.error("appliance, producer and mock must not share physical cores")
    if not args.skip_build:
        command("cargo", "build", "--release", "--locked", "-p", "rustwalld-dns", "--example", "wire_compare", timeout=600)
        command("cargo", "build", "--release", "--locked", "-p", "rustwalld-dns", timeout=600)
    pins = json.loads((ROOT / "scripts/comparison-images.json").read_text())
    for info in pins.values():
        command("docker", "pull", info["image"], timeout=300)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    identity = "rustwalld-compare-" + uuid.uuid4().hex[:12]
    image = identity + ":local"
    report = {"format": 1, "passed": False, "profile": "history-enabled, isolated UDP/TCP, closed-loop",
              "pins": pins, "rules": args.rules, "iterations": args.iterations,
              "concurrency": args.concurrency, "rounds": args.rounds, "cpus": dict(zip(("appliance", "producer", "upstream"), cpus)),
              "queries_per_second_limit": args.queries_per_second,
              "hardware": next(line.split(":",1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name")),
              "os": platform.platform(), "rows": [], "preflight": [],
              "products": args.products, "scenarios": args.scenarios, "transports": args.transports,
              "controller_sha256": sha(Path(__file__)),
              "container_recipe_sha256": sha(ROOT / "packaging/comparison.Dockerfile"),
              "image_ids": {product: command("docker", "image", "inspect", "--format", "{{.Id}}", info["image"]) for product,info in pins.items()},
              "rustc": command("rustc", "-Vv"), "docker": command("docker", "version", "--format", "{{.Server.Version}}"),
              "cache_limits": {"rustwalld_entries": 4096, "pihole_entries": 4096, "adguard_bytes": 4194304},
              "limits": {"appliance_cpus": 1, "appliance_memory_bytes": 536870912, "shared_memory_bytes": args.shared_memory_mib*1048576, "history_enabled": True},
              "daemon_path": str(args.binary.resolve()), "daemon_sha256": sha(args.binary),
              "driver_sha256": sha(ROOT / "target/release/examples/wire_compare")}
    resources = []
    try:
        with tempfile.TemporaryDirectory(prefix=identity, dir=ROOT / "target") as temporary:
            directory = Path(temporary)
            for source,name in [(ROOT / "target/release/examples/wire_compare","wire_compare"),(args.binary,"rustwalld-dns")]:
                shutil.copyfile(source, directory / name)
                (directory / name).chmod(0o755)
            command("docker", "build", "-f", str(ROOT / "packaging/comparison.Dockerfile"), "-t", image, str(directory))
            schema = command("docker", "run", "--rm", "--network", "none", "--entrypoint", "/bin/cat", pins["pihole"]["image"], "/etc/.pihole/advanced/Templates/gravity.db.sql")
            report["schema_sha256"] = hashlib.sha256(schema.encode()).hexdigest()
            report["dataset_sha256"] = fixtures(directory,args.rules,schema)
            report["config_sha256"] = {name: sha(directory / name) for name in ("rustwalld.toml","rules-rust.txt","allow-rust.txt","AdGuardHome.yaml")}
            for round_number in range(args.rounds):
                offset = round_number % len(args.products)
                order = args.products[offset:] + args.products[:offset]
                for product in order:
                    active = []
                    container = identity + f"-{round_number}-{product}"
                    try:
                        namespace = identity + f"-fixture-{round_number}-{product}"
                        fixture_args = ["docker","run","-d","--name",namespace,"--network","none","--read-only","--cpuset-cpus",str(args.upstream_cpu),"--cpus","1","--memory","512m",image,"serve"]
                        if args.inject_wrong_answer: fixture_args += ["--inject-wrong-answer"]
                        active.append(namespace); resources.append(namespace)
                        command(*fixture_args)
                        options = ["docker","create","--name",container,"--network","container:"+namespace,"--cpuset-cpus",str(args.server_cpu),"--cpus","1","--memory","512m","--memory-swap","512m","--shm-size",str(args.shared_memory_mib)+"m","--ulimit","core=0","--no-healthcheck"]
                        if product == "rustwalld":
                            options += ["-e","RUSTWALLD_API_TOKEN=comparison-only-token-0123456789","--entrypoint","/daemon",image,"--config","/work/rustwalld.toml"]
                        elif product == "pihole":
                            native_settings = {"dns.port":"5353","dns.upstreams":"127.0.0.1#1053","dns.listeningMode":"ALL","dns.blocking.mode":"NX","dns.rateLimit.count":"0","dns.cache.size":"4096","dns.cache.optimizer":"-1","resolver.resolveIPv4":"false","resolver.resolveIPv6":"false","ntp.sync.active":"false","webserver.api.password":"comparison-only-token","dns.ignoreLocalhost":"false","misc.dnsmasq_lines":"server=/bench.test/127.0.0.1#1053;max-tcp-connections=64","misc.nice":"0"}
                            report["pihole_settings"] = native_settings
                            for name,value in native_settings.items():
                                options += ["-e","FTLCONF_"+name.replace(".","_")+"="+value]
                            options += ["-e","SKIPGRAVITYONBOOT=1",pins[product]["image"]]
                        else:
                            options += [pins[product]["image"],"--no-check-update","--config","/opt/adguardhome/conf/AdGuardHome.yaml","--work-dir","/opt/adguardhome/work"]
                        active.append(container); resources.append(container)
                        command(*options)
                        if product == "rustwalld":
                            for name in ("rustwalld.toml","rules-rust.txt","allow-rust.txt"): command("docker","cp",str(directory/name),container+":/work/"+name)
                        elif product == "pihole":
                            command("docker","cp",str(directory/"gravity.db"),container+":/etc/pihole/gravity.db")
                        else:
                            command("docker","cp",str(directory/"AdGuardHome.yaml"),container+":/opt/adguardhome/conf/AdGuardHome.yaml")
                            command("docker","cp",str(directory/"adguard-work")+"/.",container+":/opt/adguardhome/work")
                        command("docker","start",container)
                        check_name = identity + f"-check-{round_number}-{product}"
                        resources.append(check_name)
                        checked = json.loads(command("docker","run","--rm","--name",check_name,"--network","container:"+namespace,"--cpuset-cpus",str(args.driver_cpu),image,"check","--rules",str(args.rules),timeout=110))
                        if checked.get("passed") is not True: raise ValueError("preflight rejected answers")
                        report["preflight"].append({"product":product,"round":round_number+1,**checked})
                        group = cgroup(container)
                        pid = dns_pid(container,product)
                        report["preflight"][-1]["cgroup"] = str(group)
                        for transport in args.transports:
                            for scenario in args.scenarios:
                                iterations = 64 if scenario == "coalescing" else min(args.iterations,200) if scenario == "cold" else args.iterations
                                concurrency = 64 if scenario == "coalescing" else args.concurrency
                                name = identity+f"-driver-{len(report['rows'])}"
                                rate = 0 if scenario in ("cold","coalescing") else args.queries_per_second
                                row = benchmark(image,namespace,group,pid,args.driver_cpu,scenario,transport,iterations,concurrency,args.rules,round_number*2+(transport=="tcp"),rate,name,resources)
                                row.update({"product":product,"round":round_number+1})
                                report["rows"].append(row)
                                print(f"{product} round={round_number+1} {transport}/{scenario}: p99={row['histogram']['p99_us']}us upstream={row['upstream_requests']}",flush=True)
                        if product == "pihole":
                            report.setdefault("shared_memory",{})[container] = command("docker","exec",container,"df","-k","/dev/shm",timeout=15)
                        observed = history_evidence(container,namespace,product,pins["pihole"]["image"],directory,
                                                    identity+f"-history-{round_number}-{product}",resources)
                        report.setdefault("history",[]).append({"product":product,"round":round_number+1,**observed})
                        if args.queries_per_second and product == "rustwalld":
                            validate_paced_history(observed)
                    except (RuntimeError, ValueError, TimeoutError, subprocess.SubprocessError) as error:
                        report.setdefault("failures",[]).append({"product":product,"round":round_number+1,"error":str(error)})
                        print(f"{product} round={round_number+1} FAILED: {error}",flush=True)
                    finally:
                        for name in reversed(active):
                            try:
                                report.setdefault("container_states",{})[name] = json.loads(command("docker","inspect","--format","{{json .State}}",name,timeout=15))
                            except (subprocess.SubprocessError, RuntimeError): pass
                            try:
                                if product == "pihole" and name == container:
                                    if name not in report.get("shared_memory",{}):
                                        report.setdefault("shared_memory",{})[name] = command("docker","exec",name,"df","-k","/dev/shm",timeout=15)
                            except (subprocess.SubprocessError, RuntimeError): pass
                            try:
                                report.setdefault("logs",{})[name] = command("docker","logs","--tail","200",name,timeout=15)[-64000:]
                            except (subprocess.SubprocessError, RuntimeError): pass
                            subprocess.run(["docker","rm","-f","-v",name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30,check=False)
            report["passed"] = not report.get("failures")
            if not report["passed"]:
                raise ValueError("appliance comparison failed; see retained product/round failures")
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        for name in reversed(resources):
            subprocess.run(["docker","rm","-f","-v",name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30,check=False)
        subprocess.run(["docker","image","rm",image],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30,check=False)
        args.output.write_text(json.dumps(report,indent=2,allow_nan=False)+"\n")
    print(args.output)


if __name__ == "__main__":
    main()
