"""Real Unbound compatibility, isolated from public DNS and host configuration."""
import json
import datetime
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time
import urllib.request


def exchange(port, domain, tcp=False, qtype=1, ad_requested=False):
    question = b"".join(bytes([len(label)]) + label.encode() for label in domain.split("."))
    wire = struct.pack("!6H", 0x1234, 0x0120 if ad_requested else 0x0100, 1, 0, 0, 0) + question + b"\0" + struct.pack("!2H", qtype, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as client:
        client.settimeout(3)
        client.connect(("127.0.0.1", port))
        if tcp:
            client.sendall(struct.pack("!H", len(wire)) + wire)

            def read(size):
                chunks = bytearray()
                while len(chunks) < size:
                    chunk = client.recv(size - len(chunks))
                    if not chunk:
                        raise RuntimeError("DNS TCP closed before complete reply")
                    chunks.extend(chunk)
                return bytes(chunks)

            response = read(struct.unpack("!H", read(2))[0])
        else:
            client.send(wire)
            response = client.recv(4096)
    if response[:2] != wire[:2] or not response[2] & 0x80:
        raise RuntimeError("invalid DNS reply envelope")
    return response[3] & 15, struct.unpack("!H", response[6:8])[0], response


def wait_ready(check):
    deadline = time.monotonic() + 10
    while True:
        try:
            return check()
        except (OSError, urllib.error.URLError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)


def run():
    # Validate the real distro configuration, including its trust-anchor setup.
    subprocess.run(["unbound-checkconf"], check=True)
    version = subprocess.check_output(["unbound", "-V"], text=True).splitlines()[0]
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        zone = root / "signed.zone"
        zone.write_text('''$ORIGIN signed.fixture.
$TTL 60
@ IN SOA ns.signed.fixture. hostmaster.signed.fixture. 1 60 60 600 60
@ IN NS ns.signed.fixture.
ns IN A 127.0.0.1
allowed IN A 192.0.2.70
bogus IN A 192.0.2.71
''')
        ksk = subprocess.check_output(["ldns-keygen", "-a", "ECDSAP256SHA256", "-k", "signed.fixture."], cwd=root, text=True).strip()
        zsk = subprocess.check_output(["ldns-keygen", "-a", "ECDSAP256SHA256", "signed.fixture."], cwd=root, text=True).strip()
        now = datetime.datetime.now(datetime.timezone.utc)
        subprocess.run(["ldns-signzone", "-i", (now-datetime.timedelta(days=1)).strftime("%Y%m%d%H%M%S"), "-e", (now+datetime.timedelta(days=365)).strftime("%Y%m%d%H%M%S"), str(zone), ksk, zsk], cwd=root, check=True)
        signed = root / "signed.zone.signed"
        text = signed.read_text()
        assert "192.0.2.71" in text
        signed.write_text(text.replace("192.0.2.71", "192.0.2.99"))
        named_config = root / "named.conf"
        named_config.write_text(f'''options {{directory "{root}"; listen-on port 5454 {{127.0.0.1;}}; listen-on-v6 {{none;}}; recursion no; dnssec-validation no; pid-file "{root / 'named.pid'}"; session-keyfile "{root / 'session.key'}";}};
controls {{}};
zone "signed.fixture" {{type primary; file "{signed}"; allow-transfer {{none;}};}};
''')
        unbound_config = root / "unbound.conf"
        unbound_config.write_text(Path("/etc/unbound/unbound.conf.d/rustwalld.conf").read_text() + '''
    username: ""
    chroot: ""
    directory: "/tmp"
    pidfile: ""
    use-syslog: no
    local-zone: "fixture.test." static
    local-data: "fixture.test. 60 IN SOA ns.fixture.test. hostmaster.fixture.test. 1 60 60 600 60"
    local-data: "allowed.fixture.test. 60 IN A 192.0.2.77"
    local-data: "ads.fixture.test. 60 IN A 192.0.2.88"
''' + f'''
    do-not-query-localhost: no
    trust-anchor-file: "{root / (ksk + '.key')}"
stub-zone:
    name: "signed.fixture."
    stub-addr: 127.0.0.1@5454
    stub-prime: no
''')
        subprocess.run(["unbound-checkconf", str(unbound_config)], check=True)
        config = root / "rustwalld.toml"
        config.write_text(f'''dns_listen = "127.0.0.1:15353"
api_listen = "127.0.0.1:18081"
database = "{root / 'state.sqlite'}"
[policy]
default_policy = "default"
allowed_clients = ["127.0.0.1/32"]
[[policy.upstreams]]
name = "unbound"
addresses = ["127.0.0.1:5335"]
timeout_ms = 1500
[[policy.policies]]
name = "default"
upstream = "unbound"
[[policy.policies.lists]]
name = "fixture"
action = "block"
rules = "ads.fixture.test"
''')
        children = []
        try:
            children.append(subprocess.Popen(["named", "-g", "-u", "root", "-c", str(named_config)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            wait_ready(lambda: exchange(5454, "allowed.signed.fixture"))
            children.append(subprocess.Popen(["unbound", "-d", "-c", str(unbound_config)]))
            wait_ready(lambda: exchange(5335, "allowed.fixture.test"))
            env = os.environ | {"RUSTWALLD_API_TOKEN": "isolated-unbound-fixture-token"}
            children.append(subprocess.Popen(["/binary/rustwalld-dns", "--config", str(config)], env=env))
            wait_ready(lambda: urllib.request.urlopen("http://127.0.0.1:18081/healthz", timeout=1).read())
            checks = 0
            valid = exchange(5335, "allowed.signed.fixture", ad_requested=True)
            assert valid[0] == 0 and valid[2][3] & 0x20, "signed local zone did not validate"
            assert exchange(5335, "bogus.signed.fixture")[0] == 2, "tampered signature was accepted"
            checks += 2
            for tcp in (False, True):
                valid = exchange(15353, "allowed.signed.fixture", tcp=tcp)
                assert valid[0] == 0 and not valid[2][3] & 0x20
                checks += 1
                for _ in range(2):
                    code, answers, wire = exchange(15353, "allowed.fixture.test", tcp)
                    assert (code, answers) == (0, 1)
                    assert socket.inet_aton("192.0.2.77") in wire
                    checks += 1
                assert exchange(15353, "ads.fixture.test", tcp)[:2] == (3, 0)
                assert exchange(15353, "missing.fixture.test", tcp)[:2] == (3, 0)
                assert exchange(15353, "allowed.fixture.test", tcp, 28)[:2] == (0, 0)
                checks += 3
                assert exchange(15353, "bogus.signed.fixture", tcp=tcp)[0] == 2
                checks += 1
            metrics = urllib.request.urlopen("http://127.0.0.1:18081/metrics", timeout=1).read().decode()
            counters = dict(line.split() for line in metrics.splitlines() if line.startswith("rustwalld_") and "{" not in line)
            assert int(counters["rustwalld_dns_cache_hits_total"]) >= 3
            assert int(counters["rustwalld_blocked_total"]) == 2
            assert int(counters["rustwalld_failures_total"]) == 2
            print(json.dumps({"unbound": version, "checks": checks, "transports": ["udp", "tcp"],
                              "public_dns": False, "dnssec_validation_tested": True,
                              "cache_hits": int(counters["rustwalld_dns_cache_hits_total"])}))
        finally:
            for child in reversed(children):
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)


if __name__ == "__main__":
    run()
