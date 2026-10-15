import contextlib
import http.server
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
from soak_tls_fixture import Certificates

SCRIPT = Path(__file__).resolve().parents[1] / "soak-collect.py"
spec = importlib.util.spec_from_file_location("soak_collect", SCRIPT)
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)
METRICS = ("rustwalld_requests_total 12\n"
           "rustwalld_dns_cache_hits_total 4\n"
           "rustwalld_history_write_failures_total 0\n")
STATUS = '{"generation":7,"cache_entries":3,"inflight":0}'


def proc_hex(address):
    packed = ipaddress.ip_address(address).packed
    return "".join(f"{int.from_bytes(packed[index:index + 4], sys.byteorder):08X}"
                   for index in range(0, len(packed), 4))


def tcp_table(*rows):
    return "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n" + "".join(
        f"0: {proc_hex(address)}:{port:04X} 00000000:0000 0A 0:0 0:0 0 0 0 {inode}\n"
        for address, port, inode in rows)


@contextlib.contextmanager
def api_fixture(family=socket.AF_INET, behavior=None, tls=None):
    state = {"status": STATUS, "metrics": METRICS, "requests": [], "behavior": behavior, "alpn": []}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            state["requests"].append(self.path)
            if tls is not None:
                state["alpn"].append(self.connection.selected_alpn_protocol())
            if state["behavior"]:
                code, body = state["behavior"](self.path)
            else:
                code = 200
                body = state["status"] if self.path == "/api/v1/status" else state["metrics"]
            if isinstance(body, str):
                body = body.encode()
            self.send_response(code)
            for name, value in state.get("headers", [("Content-Length", str(len(body)))]):
                self.send_header(name, value)
            self.end_headers()
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(body)

        def log_message(self, *_args):
            pass

    class Server(http.server.ThreadingHTTPServer):
        address_family = family
        daemon_threads = True

    host = "127.0.0.1" if family == socket.AF_INET else "::1"
    server = Server((host, 0), Handler)
    if tls is not None:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        scheme = "https" if tls is not None else "http"
        state["url"] = f"{scheme}://{host}:{port}" if family == socket.AF_INET else f"{scheme}://[{host}]:{port}"
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class Parsers(unittest.TestCase):
    def test_proc_comm_with_spaces_and_parentheses_and_real_start_ticks(self):
        text = "123 (a ) strange ( process)) " + " ".join(["S"] + ["0"] * 18 + ["987"])
        self.assertEqual(collector.start_ticks(text, 123), 987)
        for value in (text, text[:20], text.replace("987", "-1")):
            with self.assertRaises(collector.CollectionError):
                collector.start_ticks(value, 124)
        current = Path(f"/proc/{os.getpid()}/stat").read_text()
        self.assertGreater(collector.start_ticks(current, os.getpid()), 0)

    def test_process_resource_units_presence_duplicates_and_zero(self):
        self.assertEqual(collector.process_resources("VmRSS: 123 kB\nThreads: 4\n"), (123, 4))
        self.assertEqual(collector.process_resources("VmRSS: 0 kB\nThreads: 0\n"), (0, 0))
        for value in ("VmRSS: 2 MB\nThreads: 1", "Threads: 1", "VmRSS: 1 kB",
                      "VmRSS: -1 kB\nThreads: 1", "VmRSS: 1\nThreads: 1",
                      "VmRSS: 1 kB\nVmRSS: 1 kB\nThreads: 1",
                      "VmRSS: 1 kB\nThreads: 1\nThreads: 2", "VmRSS: 1 kB\nThreads: 1 x"):
            with self.subTest(value=value), self.assertRaises(collector.CollectionError):
                collector.process_resources(value)

    def test_u64_and_status_refuse_boolean_overflow_missing_duplicates(self):
        self.assertEqual(collector.u64(collector.U64_MAX), collector.U64_MAX)
        for value in (True, False, -1, collector.U64_MAX + 1, "1", 1.0, None):
            with self.subTest(value=value), self.assertRaises(collector.CollectionError):
                collector.u64(value)
        self.assertEqual(collector.status_values(STATUS), (7, 3, 0))
        for text in (STATUS.replace("7", "true"), STATUS.replace("7", "-1"),
                     STATUS.replace("7", str(collector.U64_MAX + 1)),
                     STATUS.replace('"generation":7', '"generation":7,"generation":7'),
                     '{"generation":1,"inflight":0}', "[]", STATUS.replace("7", "NaN")):
            with self.subTest(text=text), self.assertRaises(collector.CollectionError):
                collector.status_values(text)

    def test_real_counter_names_and_strict_counter_values(self):
        self.assertEqual(collector.metric_values(METRICS),
                         {"requests": 12, "cache_hits": 4, "history_failures": 0})
        self.assertEqual(collector.metric_values("# TYPE ignored counter\nignored 10\n" + METRICS),
                         collector.metric_values(METRICS))
        for text in (METRICS + "rustwalld_requests_total 12\n", METRICS.splitlines()[0],
                     METRICS.replace(" 12", " -1"), METRICS.replace(" 12", " true"),
                     METRICS.replace(" 12", " 1.0"), METRICS.replace(" 12", " 12 123"),
                     METRICS.replace(" 12", f" {collector.U64_MAX + 1}"),
                     METRICS.replace("requests_total ", 'requests_total{a="b"} ')):
            with self.subTest(text=text), self.assertRaises(collector.CollectionError):
                collector.metric_values(text)

    def test_url_restrictions(self):
        self.assertEqual(collector.endpoint("http://127.0.0.1:80"),
                         (ipaddress.ip_address("127.0.0.1"), 80))
        self.assertEqual(collector.endpoint("http://[::1]:1234")[1], 1234)
        self.assertEqual(collector.endpoint("https://127.0.0.1:8443")[1], 8443)
        for url in ("ftp://127.0.0.1:80", "http://localhost:80", "http://8.8.8.8:80",
                    "http://127.0.0.1", "http://127.0.0.1:0", "http://127.0.0.1:65536",
                    "http://127.0.0.1:80/", "http://127.0.0.1:80?a=b",
                    "http://127.0.0.1:80#fragment", "http://u:p@127.0.0.1:80",
                    "http://@127.0.0.1:80", "http://127.0.0.1:\t80", "http://[::1%lo]:80"):
            with self.subTest(url=url), self.assertRaises((collector.CollectionError, ValueError)):
                collector.endpoint(url)

    def test_native_endian_tcp_addresses_and_ownership(self):
        for address in ("127.0.0.1", "::1", "2001:db8:1:2:3:4:5:6"):
            ip = ipaddress.ip_address(address)
            self.assertEqual(collector.proc_address(proc_hex(address), ip.version), ip)
        address = ipaddress.ip_address("127.0.0.1")
        for rows, owned, passes in (
                ([("127.0.0.1", 80, 42)], {42}, True),
                ([("0.0.0.0", 80, 42)], {42}, True),
                ([("127.0.0.1", 80, 43)], {42}, False),
                ([("127.0.0.1", 81, 42)], {42}, False),
                ([("127.0.0.1", 80, 42), ("0.0.0.0", 80, 43)], {42}, False)):
            with self.subTest(rows=rows), mock.patch.object(collector, "read_regular", side_effect=[
                    tcp_table(*rows), tcp_table()]):
                if passes:
                    self.assertEqual(collector.verify_listener(1, owned, address, 80), {42})
                else:
                    with self.assertRaises(collector.CollectionError):
                        collector.verify_listener(1, owned, address, 80)
        with mock.patch.object(collector, "read_regular", side_effect=[
                tcp_table(("127.0.0.1", 80, 42)), tcp_table(("::", 80, 42))]):
            with self.assertRaises(collector.CollectionError):
                collector.verify_listener(1, {42}, address, 80)


class Filesystem(unittest.TestCase):
    def test_regular_file_caps_and_special_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "regular").write_bytes(b"1234")
            self.assertEqual(collector.read_regular(root / "regular", 4), "1234")
            with self.assertRaises(collector.CollectionError):
                collector.read_regular(root / "regular", 3)
            (root / "link").symlink_to(root / "regular")
            os.mkfifo(root / "fifo")
            for name in ("link", "fifo"):
                with self.assertRaises((collector.CollectionError, OSError)):
                    collector.read_regular(root / name, 4)

    def test_storage_nested_sizes_symlink_special_depth_and_entry_limits(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "state").mkdir()
            (root / "state" / "db").write_bytes(b"123")
            (root / "db-wal").write_bytes(b"45")
            self.assertEqual(collector.storage_bytes(root), 5)
            with mock.patch.object(collector, "ENTRY_LIMIT", 2), self.assertRaises(collector.CollectionError):
                collector.storage_bytes(root)
            with mock.patch.object(collector, "DEPTH_LIMIT", 0), self.assertRaises(collector.CollectionError):
                collector.storage_bytes(root)
            (root / "db-shm").symlink_to(root / "db-wal")
            with self.assertRaises(collector.CollectionError):
                collector.storage_bytes(root)
            (root / "db-shm").unlink()
            os.mkfifo(root / "fifo")
            with self.assertRaises(collector.CollectionError):
                collector.storage_bytes(root)
            (root / "root-link").symlink_to(root / "state", target_is_directory=True)
            with self.assertRaises(OSError):
                collector.storage_bytes(root / "root-link")

    def test_storage_swap_to_symlink_does_not_follow_external_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            storage, outside = root / "storage", root / "outside"
            storage.mkdir()
            (storage / "child").mkdir()
            outside.mkdir()
            (outside / "secret").write_bytes(b"must not count")
            original_open = collector.os.open

            def swap(path, flags, **kwargs):
                if path == "child":
                    (storage / "child").rename(storage / "old")
                    (storage / "child").symlink_to(outside, target_is_directory=True)
                return original_open(path, flags, **kwargs)

            with mock.patch.object(collector.os, "open", side_effect=swap):
                with self.assertRaises(OSError):
                    collector.storage_bytes(storage)

    def test_storage_disappearance_and_checked_sum(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "db").write_bytes(b"1234")
            with mock.patch.object(collector, "U64_MAX", 3), self.assertRaises(collector.CollectionError):
                collector.storage_bytes(root)
            original_open = collector.os.open

            def disappear(path, flags, **kwargs):
                if path == "db":
                    (root / "db").unlink()
                return original_open(path, flags, **kwargs)

            with mock.patch.object(collector.os, "open", side_effect=disappear):
                with self.assertRaises(FileNotFoundError):
                    collector.storage_bytes(root)

    def test_fd_enumeration_is_bounded(self):
        descriptor = os.open(f"/proc/{os.getpid()}", collector.DIRECTORY_FLAGS)
        try:
            count, _ = collector.owned_fds(descriptor)
            self.assertGreater(count, 0)
            with mock.patch.object(collector, "ENTRY_LIMIT", 0), self.assertRaises(collector.CollectionError):
                collector.owned_fds(descriptor)
        finally:
            os.close(descriptor)


class Cli(unittest.TestCase):
    def command(self, api, storage, *extra):
        pid = os.getpid()
        ticks = collector.start_ticks(Path(f"/proc/{pid}/stat").read_text(), pid)
        return [sys.executable, str(SCRIPT), "--run-id", "owned-test", "--target-id", "fixture",
                "--pid", str(pid), "--start-ticks", str(ticks), "--api-url", api["url"],
                "--storage-directory", str(storage), "--sequence", "9", *extra]

    def invoke(self, api, storage, *extra, env=None):
        return subprocess.run(self.command(api, storage, *extra), capture_output=True,
                              timeout=4, env=env)

    def assert_failure(self, result):
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertNotIn(b"Traceback", result.stderr)

    def test_owned_http_cli_and_proxy_environment_not_used(self):
        with tempfile.TemporaryDirectory() as temporary, api_fixture() as api:
            root = Path(temporary)
            (root / "db").write_bytes(b"12345")
            environment = dict(os.environ, http_proxy="http://127.0.0.1:1",
                               HTTP_PROXY="http://127.0.0.1:1", ALL_PROXY="http://127.0.0.1:1", NO_PROXY="")
            before = time.time_ns() // 1000000
            result = self.invoke(api, root, env=environment)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertLessEqual(len(result.stdout), collector.SAMPLE_BYTES)
            self.assertTrue(result.stdout.endswith(b"\n"))
            sample = json.loads(result.stdout)
            self.assertEqual(sample["run_id"], "owned-test")
            self.assertEqual(sample["sequence"], 9)
            self.assertEqual(sample["generation"], 7)
            self.assertEqual(sample["resources"][3:], [5, 3, 0])
            self.assertTrue(all(value > 0 for value in sample["resources"][:3]))
            self.assertEqual(sample["counters"], collector.metric_values(METRICS))
            self.assertGreaterEqual(sample["unix_ms"], before)
            self.assertEqual(api["requests"], ["/api/v1/status", "/metrics", "/api/v1/status"])

    @unittest.skipUnless(socket.has_ipv6, "IPv6 unavailable")
    def test_ipv6_owned_listener(self):
        with tempfile.TemporaryDirectory() as temporary:
            try:
                with api_fixture(socket.AF_INET6) as api:
                    result = self.invoke(api, Path(temporary))
            except OSError as error:
                if error.errno in (97, 99):
                    self.skipTest("IPv6 loopback unavailable")
                raise
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_pid_listener_generation_and_invalid_status_fail_without_stdout(self):
        with tempfile.TemporaryDirectory() as temporary, api_fixture() as api:
            root = Path(temporary)
            self.assert_failure(self.invoke(api, root, "--start-ticks", "0"))
            self.assertEqual(api["requests"], [])
            # The API socket belongs to the test parent, not this collector child.
            command = self.command(api, root)
            command[command.index("--pid") + 1] = "1"
            self.assert_failure(subprocess.run(command, capture_output=True, timeout=4))
            api["status"] = STATUS.replace("7", "true")
            self.assert_failure(self.invoke(api, root))
            status_count = 0

            def changed(path):
                nonlocal status_count
                if path == "/api/v1/status":
                    status_count += 1
                    return 200, STATUS.replace("7", str(6 + status_count))
                return 200, METRICS

            api["behavior"] = changed
            self.assert_failure(self.invoke(api, root))

    def test_redirect_oversized_malformed_and_deadline_fail_without_stdout(self):
        with tempfile.TemporaryDirectory() as temporary, api_fixture() as api:
            root = Path(temporary)
            for code, text in ((302, b"redirect"), (200, b"x" * (collector.HTTP_BYTES + 1)),
                               (200, b"{"), (200, b"\xff"),
                               (200, b'{"generation":7,"cache_entries":3,"inflight":0,"unused":'
                                + b"[" * 5000 + b"0" + b"]" * 5000 + b"}")):
                api["behavior"] = lambda _path, code=code, text=text: (code, text)
                self.assert_failure(self.invoke(api, root))

            def stalled(_path):
                time.sleep(.3)
                return 200, STATUS

            api["behavior"] = stalled
            start = time.monotonic()
            self.assert_failure(self.invoke(api, root, "--deadline-ms", "100"))
            self.assertLess(time.monotonic() - start, 1)

    def test_truncated_or_ambiguous_http_framing_fails_without_stdout(self):
        for headers in (f"Content-Length: {len(STATUS) + 5}\r\n",
                        f"Content-Length: {len(STATUS)}\r\nContent-Length: {len(STATUS)}\r\n",
                        f"Content-Length: {len(STATUS)}\r\nContent-Length: {len(STATUS) + 5}\r\n",
                        f"Content-Length: {len(STATUS)}\r\nTransfer-Encoding: chunked\r\n",
                        f"Content-Length: {len(STATUS)}\r\nTransfer-Encoding: gzip\r\n",
                        "Content-Length: -1\r\n", "Content-Length: invalid\r\n", ""):
            with self.subTest(headers=headers), tempfile.TemporaryDirectory() as temporary:
                listener = socket.socket()
                listener.bind(("127.0.0.1", 0))
                listener.listen()
                listener.settimeout(2)

                def respond():
                    with listener.accept()[0] as connection:
                        connection.recv(4096)
                        connection.sendall(("HTTP/1.1 200 OK\r\n" + headers
                                            + "Connection: close\r\n\r\n" + STATUS).encode())

                thread = threading.Thread(target=respond, daemon=True)
                thread.start()
                try:
                    api = {"url": f"http://127.0.0.1:{listener.getsockname()[1]}"}
                    self.assert_failure(self.invoke(api, Path(temporary)))
                finally:
                    listener.close()
                    thread.join(timeout=3)
                self.assertFalse(thread.is_alive())

    def test_namespace_mismatch_and_output_watchdog_boundary(self):
        args = type("Args", (), {"api_url": "http://127.0.0.1:80", "pid": os.getpid(),
                                "start_ticks": collector.start_ticks(
                                    Path(f"/proc/{os.getpid()}/stat").read_text(), os.getpid())})()
        original = collector.os.readlink

        def namespace(path, **kwargs):
            return "net:[different]" if path == "ns/net" else original(path, **kwargs)

        with mock.patch.object(collector.os, "readlink", side_effect=namespace):
            with self.assertRaises(collector.CollectionError):
                collector.collect(args, collector.Deadline(750))
        with mock.patch.object(collector, "arguments", return_value=type("Args", (), {"deadline_ms": 100})()), \
                mock.patch.object(collector, "collect", return_value={"observed": 1}), \
                mock.patch.object(collector.sys, "stdout") as output:
            output.buffer.write.side_effect = lambda _payload: self.assertEqual(
                signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
            self.assertEqual(collector.main([]), 0)

    def test_recursion_failure_is_sanitized_before_stdout(self):
        errors = io.StringIO()
        args = type("Args", (), {"deadline_ms": 100})()
        with mock.patch.object(collector, "arguments", return_value=args), \
                mock.patch.object(collector, "collect", side_effect=RecursionError("untrusted-marker")), \
                mock.patch.object(collector.sys, "stdout") as output, \
                mock.patch.object(collector.sys, "stderr", errors):
            self.assertEqual(collector.main([]), 1)
            output.buffer.write.assert_not_called()
            output.buffer.flush.assert_not_called()
        self.assertEqual(errors.getvalue(),
                         "soak collection failed; no complete successful observation\n")
        self.assertNotIn("untrusted-marker", errors.getvalue())


class Https(unittest.TestCase):
    command = Cli.command
    invoke = Cli.invoke
    assert_failure = Cli.assert_failure

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.certificates = Certificates(Path(cls.temporary.name) / "trusted")
        cls.other = Certificates(Path(cls.temporary.name) / "other")

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def options(self, identity="collector.test", ca=None):
        return ["--tls-ca-file", str(ca or self.certificates.ca), "--tls-server-name", identity]

    def test_trusted_dns_and_ip_san_use_explicit_identity_and_http11(self):
        context = self.certificates.context()
        names = []
        context.set_servername_callback(lambda _socket, name, _context: names.append(name))
        with tempfile.TemporaryDirectory() as temporary, api_fixture(tls=context) as api:
            for identity in ("collector.test", "127.0.0.1", "::1"):
                result = self.invoke(api, Path(temporary), *self.options(identity))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)["generation"], 7)
            self.assertEqual(api["alpn"], ["http/1.1"] * 9)
            self.assertEqual(names, ["collector.test"] * 3 + [None] * 6)

    def test_wrong_ca_name_and_cn_only_fail_before_http(self):
        with tempfile.TemporaryDirectory() as temporary, api_fixture(tls=self.certificates.context()) as api:
            self.assert_failure(self.invoke(api, Path(temporary), *self.options("wrong.test")))
            self.assert_failure(self.invoke(api, Path(temporary), *self.options(ca=self.other.ca)))
            self.assertEqual(api["requests"], [])
        with tempfile.TemporaryDirectory() as temporary, api_fixture(
                tls=self.certificates.context("cn-only")) as api:
            self.assert_failure(self.invoke(api, Path(temporary), *self.options()))
            self.assertEqual(api["requests"], [])

    def test_missing_mixed_and_invalid_identity_options_fail(self):
        with tempfile.TemporaryDirectory() as temporary, api_fixture(tls=self.certificates.context()) as api:
            for options in ([], ["--tls-ca-file", str(self.certificates.ca)],
                            ["--tls-server-name", "collector.test"]):
                self.assert_failure(self.invoke(api, Path(temporary), *options))
            self.assertEqual(api["requests"], [])
        with tempfile.TemporaryDirectory() as temporary, api_fixture() as api:
            for options in (self.options(), ["--tls-ca-file", str(self.certificates.ca)],
                            ["--tls-server-name", "collector.test"]):
                self.assert_failure(self.invoke(api, Path(temporary), *options))
            self.assertEqual(api["requests"], [])
        for identity in ("", "a.", "*.test", "a..test", "a/b", "a:80", "[::1]",
                         "a_b.test", "-bad.test", "bad-.test", "café.test", "127.0.0.999",
                         "a" * 64 + ".test", "a\ntest", "::1%lo"):
            with self.subTest(identity=identity), self.assertRaises(collector.CollectionError):
                collector.tls_identity(identity)

    def test_ca_reads_are_bounded_regular_absolute_and_no_follow(self):
        with tempfile.TemporaryDirectory() as temporary, api_fixture(tls=self.certificates.context()) as api:
            root = Path(temporary)
            for name, content in (("invalid", b"not PEM"), ("empty", b""),
                                  ("oversized", b"x" * 65537), ("nonascii", b"\xff")):
                (root / name).write_bytes(content)
            (root / "leaf").symlink_to(self.certificates.ca)
            (root / "parent").symlink_to(self.certificates.root, target_is_directory=True)
            os.mkfifo(root / "fifo")
            for ca in [root / name for name in ("invalid", "empty", "oversized", "nonascii", "leaf", "fifo")
                       ] + [root / "parent" / "ca.pem", Path("relative.pem")]:
                with self.subTest(ca=ca):
                    self.assert_failure(self.invoke(api, root, *self.options(ca=ca)))
            self.assertEqual(api["requests"], [])

    def test_hostile_environment_never_changes_trust_proxy_or_creates_keylog(self):
        with tempfile.TemporaryDirectory() as temporary, api_fixture(tls=self.certificates.context()) as api:
            root = Path(temporary)
            keylog = root / "keys.log"
            environment = dict(os.environ, SSLKEYLOGFILE=str(keylog),
                               SSL_CERT_FILE=str(self.other.ca), SSL_CERT_DIR=str(root),
                               HTTPS_PROXY="http://127.0.0.1:1", ALL_PROXY="http://127.0.0.1:1",
                               https_proxy="http://127.0.0.1:1", NO_PROXY="")
            result = self.invoke(api, root, *self.options(), env=environment)
            self.assertEqual(result.returncode, 0, result.stderr)
            environment["SSL_CERT_FILE"] = str(self.certificates.ca)
            self.assert_failure(self.invoke(api, root, *self.options(ca=self.other.ca), env=environment))
            self.assertFalse(keylog.exists())

    def test_plaintext_and_stalled_handshake_never_downgrade(self):
        with tempfile.TemporaryDirectory() as temporary, api_fixture() as api:
            api["url"] = api["url"].replace("http:", "https:")
            self.assert_failure(self.invoke(api, Path(temporary), *self.options()))
            self.assertEqual(api["requests"], [])
        with tempfile.TemporaryDirectory() as temporary, socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(2)

            def stall():
                with listener.accept()[0] as connection:
                    connection.recv(4096)
                    time.sleep(.3)

            thread = threading.Thread(target=stall, daemon=True)
            thread.start()
            try:
                api = {"url": f"https://127.0.0.1:{listener.getsockname()[1]}"}
                start = time.monotonic()
                self.assert_failure(self.invoke(api, Path(temporary), *self.options(), "--deadline-ms", "100"))
                self.assertLess(time.monotonic() - start, 1)
            finally:
                thread.join(timeout=3)
            self.assertFalse(thread.is_alive())

    def test_strict_http_framing_is_preserved_over_tls(self):
        with tempfile.TemporaryDirectory() as temporary, api_fixture(tls=self.certificates.context()) as api:
            for headers in ([("Content-Length", str(len(STATUS) + 5))],
                            [("Content-Length", str(len(STATUS)))] * 2,
                            [("Content-Length", str(len(STATUS))), ("Transfer-Encoding", "gzip")]):
                api["headers"] = headers
                self.assert_failure(self.invoke(api, Path(temporary), *self.options()))


if __name__ == "__main__":
    unittest.main()
