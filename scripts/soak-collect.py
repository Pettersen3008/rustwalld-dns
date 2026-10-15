#!/usr/bin/env python3
"""Emit one bounded Linux-local observation for the remote soak driver.

HTTP responses require one explicit Content-Length and no Transfer-Encoding.
Changing/disappearing process descriptors fail collection; the controller must
accept only complete exit-zero output before atomically publishing a sample.
"""
import argparse
import contextlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import ssl
import stat
import sys
import time
from urllib.parse import urlsplit

U64_MAX = (1 << 64) - 1
PROC_BYTES = 65536
TCP_BYTES = 1048576
HTTP_BYTES = 65536
ENTRY_LIMIT = 4096
DEPTH_LIMIT = 8
SAMPLE_BYTES = 16384
COUNTERS = {
    "rustwalld_requests_total": "requests",
    "rustwalld_dns_cache_hits_total": "cache_hits",
    "rustwalld_history_write_failures_total": "history_failures",
}
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class CollectionError(Exception):
    """An observation cannot safely be attributed or completed."""


def require(condition, message):
    if not condition:
        raise CollectionError(message)


def u64(value):
    require(type(value) is int and 0 <= value <= U64_MAX, "invalid unsigned value")
    return value


def decimal(text):
    require(isinstance(text, str) and re.fullmatch(r"[0-9]{1,20}", text),
            "invalid integer text")
    return u64(int(text))


class Deadline:
    def __init__(self, milliseconds):
        self.end = time.monotonic() + milliseconds / 1000

    def remaining(self):
        value = self.end - time.monotonic()
        require(value > 0, "collection deadline exceeded")
        return value


@contextlib.contextmanager
def watchdog(milliseconds):
    def expired(_signum, _frame):
        raise CollectionError("collection deadline exceeded")

    previous = signal.signal(signal.SIGALRM, expired)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, milliseconds / 1000)
    try:
        yield Deadline(milliseconds)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        if previous_timer != (0.0, 0.0):
            signal.setitimer(signal.ITIMER_REAL, *previous_timer)


def read_regular(path, cap, directory=None):
    descriptor = os.open(path, FILE_FLAGS, dir_fd=directory)
    try:
        require(stat.S_ISREG(os.fstat(descriptor).st_mode), "input is not regular")
        result = bytearray()
        while len(result) <= cap:
            part = os.read(descriptor, min(65536, cap + 1 - len(result)))
            if not part:
                break
            result.extend(part)
        require(len(result) <= cap, "input byte limit exceeded")
        return bytes(result).decode("utf-8")
    finally:
        os.close(descriptor)


def start_ticks(text, pid):
    prefix, separator, fields = text.rpartition(")")
    require(separator and prefix.startswith(f"{pid} ("), "invalid process stat")
    values = fields.split()
    require(len(values) >= 20 and len(values[0]) == 1, "incomplete process stat")
    return decimal(values[19])


def process_resources(text):
    selected = {}
    for line in text.splitlines():
        name, separator, value = line.partition(":")
        if name in ("VmRSS", "Threads"):
            require(separator and name not in selected, "duplicate process resource")
            selected[name] = value.split()
    require(set(selected) == {"VmRSS", "Threads"}, "missing process resource")
    require(len(selected["VmRSS"]) == 2 and selected["VmRSS"][1] == "kB",
            "invalid RSS units")
    require(len(selected["Threads"]) == 1, "invalid thread count")
    return decimal(selected["VmRSS"][0]), decimal(selected["Threads"][0])


def owned_fds(directory):
    descriptor = os.open("fd", DIRECTORY_FLAGS, dir_fd=directory)
    try:
        count, sockets = 0, set()
        with os.scandir(descriptor) as entries:
            for entry in entries:
                count += 1
                require(count <= ENTRY_LIMIT, "FD entry limit exceeded")
                target = os.readlink(entry.name, dir_fd=descriptor)
                match = re.fullmatch(r"socket:\[([0-9]{1,20})\]", target)
                if match:
                    sockets.add(decimal(match[1]))
        return count, sockets
    finally:
        os.close(descriptor)


def proc_address(text, family):
    size = 8 if family == 4 else 32
    require(len(text) == size and re.fullmatch(r"[0-9A-Fa-f]+", text),
            "invalid proc address")
    packed = b"".join(int(text[index:index + 8], 16).to_bytes(4, sys.byteorder)
                      for index in range(0, size, 8))
    return ipaddress.ip_address(packed)


def listeners(text, family):
    rows = text.splitlines()
    require(rows and rows[0].split()[:2] == ["sl", "local_address"],
            "invalid proc TCP header")
    result = []
    for row in rows[1:]:
        fields = row.split()
        require(len(fields) >= 10, "invalid proc TCP row")
        address, separator, port = fields[1].partition(":")
        require(separator and re.fullmatch(r"[0-9A-Fa-f]{4}", port),
                "invalid proc TCP port")
        ip = proc_address(address, family)
        inode = decimal(fields[9])
        if fields[3] == "0A":
            result.append((ip, int(port, 16), inode))
    return result


def verify_listener(directory, owned, address, port):
    rows = listeners(read_regular("net/tcp", TCP_BYTES, directory), 4)
    try:
        rows += listeners(read_regular("net/tcp6", TCP_BYTES, directory), 6)
    except FileNotFoundError:
        require(address.version == 4, "IPv6 proc table unavailable")
    matching = set()
    for ip, local_port, inode in rows:
        if local_port != port:
            continue
        # /proc cannot prove IPV6_V6ONLY; do not infer cross-family routing.
        require(not (address.version == 4 and ip.version == 6 and ip.is_unspecified),
                "ambiguous IPv6 wildcard listener")
        if ip.version == address.version and (ip == address or ip.is_unspecified):
            require(inode in owned, "API listener is not exclusively target-owned")
            matching.add(inode)
    require(matching, "target does not own the API listener")
    return matching


def endpoint(url):
    require(len(url) <= 256 and all(33 <= ord(char) <= 126 for char in url),
            "invalid API URL")
    parsed = urlsplit(url)
    require(parsed.scheme in ("http", "https") and not parsed.username and not parsed.password
            and not parsed.path and not parsed.query and not parsed.fragment
            and "@" not in parsed.netloc and "%" not in parsed.netloc,
            "API URL must be loopback HTTP or HTTPS without extra components")
    address = ipaddress.ip_address(parsed.hostname or "")
    require(address.is_loopback and parsed.port is not None and parsed.port > 0,
            "API URL must identify a numeric loopback port")
    return address, parsed.port


def tls_identity(text):
    require(isinstance(text, str) and 1 <= len(text) <= 253 and text.isascii()
            and "%" not in text,
            "invalid TLS identity")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        require(not re.fullmatch(r"[0-9.]+", text), "invalid numeric TLS identity")
        require(all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                    for label in text.split(".")), "invalid DNS TLS identity")
        return text


def tls_settings(args):
    ca_file = getattr(args, "tls_ca_file", None)
    identity = getattr(args, "tls_server_name", None)
    if urlsplit(args.api_url).scheme == "http":
        require(ca_file is None and identity is None, "TLS options require HTTPS")
        return None
    require(ca_file is not None and identity is not None, "HTTPS requires explicit CA and identity")
    identity = tls_identity(identity)
    require(ca_file.is_absolute() and len(str(ca_file)) <= 4096 and ".." not in ca_file.parts,
            "CA file must be an absolute bounded path")
    directory = open_directory(ca_file.parent)
    try:
        pem = read_regular(ca_file.name, 65536, directory)
    finally:
        os.close(directory)
    require(pem and pem.isascii(), "invalid CA PEM")
    # Explicit construction ignores SSLKEYLOGFILE and environment/system trust.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.hostname_checks_common_name = False
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cadata=pem)
    context.set_alpn_protocols(["http/1.1"])
    return context, identity


class VerifiedTLSConnection(http.client.HTTPConnection):
    def __init__(self, address, port, deadline, settings):
        super().__init__(str(address), port, timeout=deadline.remaining())
        self.deadline = deadline
        self.context, self.identity = settings

    def connect(self):
        try:
            super().connect()  # self.host remains the numeric loopback address.
            self.sock.settimeout(self.deadline.remaining())
            self.sock = self.context.wrap_socket(self.sock, server_hostname=self.identity)
        except BaseException:
            self.close()
            raise


def fetch(address, port, path, deadline, tls=None):
    connection = (VerifiedTLSConnection(address, port, deadline, tls) if tls is not None
                  else http.client.HTTPConnection(str(address), port, timeout=deadline.remaining()))
    try:
        connection.request("GET", path, headers={"Connection": "close", "Accept-Encoding": "identity"})
        response = connection.getresponse()
        require(response.status == 200, "API response is not successful")
        lengths = response.headers.get_all("Content-Length", [])
        require(len(lengths) == 1 and not response.headers.get_all("Transfer-Encoding", []),
                "unsupported or ambiguous HTTP framing")
        declared = decimal(lengths[0].strip())
        require(declared <= HTTP_BYTES, "HTTP body limit exceeded")
        body = response.read(HTTP_BYTES + 1)
        require(len(body) == declared, "incomplete HTTP body")
        deadline.remaining()
        return body.decode("utf-8")
    finally:
        connection.close()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def status_values(text):
    def invalid_constant(_value):
        raise CollectionError("invalid JSON constant")

    value = json.loads(text, object_pairs_hook=unique_object, parse_constant=invalid_constant)
    require(type(value) is dict, "invalid status object")
    require(all(name in value for name in ("generation", "cache_entries", "inflight")),
            "missing status field")
    return tuple(u64(value[name]) for name in ("generation", "cache_entries", "inflight"))


def metric_values(text):
    result = {}
    for line in text.splitlines():
        fields = line.split()
        if not fields or fields[0].startswith("#"):
            continue
        name = fields[0].split("{", 1)[0]
        if name in COUNTERS:
            require(fields[0] == name and len(fields) == 2 and COUNTERS[name] not in result,
                    "ambiguous selected counter")
            result[COUNTERS[name]] = decimal(fields[1])
    require(len(result) == len(COUNTERS), "missing selected counter")
    return result


def open_directory(path):
    require(path.is_absolute() and len(str(path)) <= 4096 and ".." not in path.parts,
            "storage directory must be an absolute bounded path")
    descriptor = os.open("/", DIRECTORY_FLAGS)
    try:
        for component in path.parts[1:]:
            child = os.open(component, DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def storage_bytes(path):
    root = open_directory(path)
    count, total = 0, 0

    def walk(directory, depth):
        nonlocal count, total
        with os.scandir(directory) as entries:
            for entry in entries:
                count += 1
                require(count <= ENTRY_LIMIT, "storage entry limit exceeded")
                before = os.stat(entry.name, dir_fd=directory, follow_symlinks=False)
                is_directory = stat.S_ISDIR(before.st_mode)
                require(is_directory or stat.S_ISREG(before.st_mode), "special storage entry")
                require(not is_directory or depth < DEPTH_LIMIT, "storage depth limit exceeded")
                child = os.open(entry.name, DIRECTORY_FLAGS if is_directory else FILE_FLAGS,
                                dir_fd=directory)
                try:
                    opened = os.fstat(child)
                    require((before.st_dev, before.st_ino, before.st_mode)
                            == (opened.st_dev, opened.st_ino, opened.st_mode), "storage entry changed")
                    if is_directory:
                        walk(child, depth + 1)
                    else:
                        total = u64(total + u64(opened.st_size))
                    after = os.stat(entry.name, dir_fd=directory, follow_symlinks=False)
                    require((after.st_dev, after.st_ino, after.st_mode)
                            == (opened.st_dev, opened.st_ino, opened.st_mode), "storage entry changed")
                finally:
                    os.close(child)

    try:
        walk(root, 0)
        return total
    finally:
        os.close(root)


def collect(args, deadline):
    timestamp = u64(time.time_ns() // 1000000)
    address, port = endpoint(args.api_url)
    tls = tls_settings(args)
    directory = os.open(f"/proc/{args.pid}", DIRECTORY_FLAGS)
    try:
        def verify_process():
            ticks = start_ticks(read_regular("stat", PROC_BYTES, directory), args.pid)
            require(ticks == args.start_ticks, "process identity mismatch")
            require(os.readlink("ns/net", dir_fd=directory) == os.readlink("/proc/self/ns/net"),
                    "network namespace mismatch")

        verify_process()
        fd_count, sockets = owned_fds(directory)
        ownership = verify_listener(directory, sockets, address, port)
        rss, threads = process_resources(read_regular("status", PROC_BYTES, directory))
        generation, cache, inflight = status_values(fetch(address, port, "/api/v1/status", deadline, tls))
        counters = metric_values(fetch(address, port, "/metrics", deadline, tls))
        storage = storage_bytes(args.storage_directory)
        require(status_values(fetch(address, port, "/api/v1/status", deadline, tls))[0] == generation,
                "generation changed during collection")
        verify_process()
        _, sockets = owned_fds(directory)
        require(verify_listener(directory, sockets, address, port) == ownership,
                "API listener changed during collection")
        deadline.remaining()
        return {"run_id": args.run_id, "target_id": args.target_id,
                "process_id": f"{args.pid}:{args.start_ticks}", "sequence": args.sequence,
                "unix_ms": timestamp, "generation": generation,
                "resources": [rss, fd_count, threads, storage, cache, inflight], "counters": counters}
    finally:
        os.close(directory)


def arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("run-id", "target-id", "api-url"):
        parser.add_argument(f"--{name}", required=True)
    for name in ("pid", "start-ticks", "sequence"):
        parser.add_argument(f"--{name}", type=decimal, required=True)
    parser.add_argument("--storage-directory", type=Path, required=True)
    parser.add_argument("--tls-ca-file", type=Path, help="explicit HTTPS CA PEM, read without symlinks")
    parser.add_argument("--tls-server-name", help="HTTPS certificate DNS or IP identity; never resolved")
    parser.add_argument("--deadline-ms", type=int, default=750)
    args = parser.parse_args(argv)
    for value in (args.run_id, args.target_id):
        require(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value), "invalid run or target ID")
    require(args.pid > 0, "PID must be positive")
    require(100 <= args.deadline_ms <= 2000, "deadline must be 100..2000 ms")
    require(sys.platform == "linux", "collector requires Linux")
    return args


def main(argv=None):
    try:
        args = arguments(argv)
        with watchdog(args.deadline_ms) as deadline:
            payload = (json.dumps(collect(args, deadline), separators=(",", ":"),
                                  allow_nan=False) + "\n").encode("ascii")
            require(len(payload) <= SAMPLE_BYTES, "sample byte limit exceeded")
        # The controller bounds stdout and publishes only complete exit-zero output.
        sys.stdout.buffer.write(payload)
        sys.stdout.buffer.flush()
        return 0
    except (CollectionError, OSError, ValueError, RecursionError, http.client.HTTPException):
        print("soak collection failed; no complete successful observation", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
