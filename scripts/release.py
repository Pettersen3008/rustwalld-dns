#!/usr/bin/env python3
"""Locked native Linux build and deterministic, content-addressed release bundle."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def build(output, skip_build=False, parallel_compilation=False):
    target = run("rustc", "-vV").split("host: ")[1].splitlines()[0]
    if not re.fullmatch(r"(?:x86_64|aarch64)-unknown-linux-gnu", target):
        raise ValueError("initial bundles support native x86_64/aarch64 Linux GNU only")
    if not skip_build:
        command = ["cargo", "build", "--release", "--locked", "-p", "rustwalld-dns"]
        if parallel_compilation:
            command += ["--features", "parallel-compilation"]
        subprocess.run(command, cwd=ROOT, check=True)
        subprocess.run(["npm", "--prefix", "web", "ci"], cwd=ROOT, check=True)
        subprocess.run(["npm", "--prefix", "web", "run", "build"], cwd=ROOT, check=True)
    binary = ROOT / "target/release/rustwalld-dns"
    if not binary.is_file() or not (ROOT / "web/dist/index.html").is_file():
        raise ValueError("build the release binary and console first")
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    source = {}
    for directory in ("crates", "web/src", "packaging", "scripts", "docs"):
        for path in sorted((ROOT / directory).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and not any(part.startswith(".") for part in path.relative_to(ROOT).parts):
                source[str(path.relative_to(ROOT))] = digest(path.read_bytes())
    for name in ("Cargo.toml", "Cargo.lock", "web/package.json", "web/package-lock.json", "web/vite.config.ts", "web/tsconfig.json", "web/index.html", "README.md", "rust-toolchain.toml", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md", "SUPPORT.md", "CODE_OF_CONDUCT.md", "CODEOWNERS", "pull_request_template.md"):
        source[name] = digest((ROOT / name).read_bytes())
    files = {"bin/rustwalld-dns": binary.read_bytes(),
             "systemd/rustwalld-dns.service": (ROOT / "packaging/rustwalld-dns.service").read_bytes(),
             "config/config.toml": (ROOT / "packaging/config.toml").read_bytes()}
    for name in ("README.md", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md", "SUPPORT.md", "CODE_OF_CONDUCT.md", "CODEOWNERS", "pull_request_template.md", "LICENSE-MIT", "LICENSE-APACHE", "LICENSE-WEBPKI-ROOTS"):
        files[name] = (ROOT / name).read_bytes()
    for name in ("operations.md", "encrypted-upstreams.md", "tls-baseline.md", "doh-design.md", "doh-baseline.md", "encrypted-resilience.md", "encrypted-resilience-baseline.md", "upstream-diagnostics.md", "upstream-diagnostics-baseline.md", "upstream-backoff.md", "upstream-backoff-baseline.md", "console-design.md", "offline-policy-checks.md", "temporary-exceptions.md", "downloaded-lists.md", "client-metadata.md", "scheduled-refreshes.md", "conditional-retrieval.md", "control-plane-soak.md", "filter-memory.md", "query-allocations.md", "cache-forwarding.md", "borrowed-decisions.md", "cpu-query.md", "embedding.md", "releasing.md", "refactor-results.md", "rust-1.99-performance.md", "parallel-compilation.md", "engine-split.md", "cache-eviction.md", "filter-matching.md", "doh-latency.md", "dot-pipelining.md", "serve-stale.md", "property-tests.md", "runtime-modules.md", "release-rebuild.md"):
        files["docs/" + name] = (ROOT / "docs" / name).read_bytes()
    for crate in ("filtering", "resolver", "policy", "dns-core", "runtime"):
        files[f"crates/{crate}/README.md"] = (ROOT / "crates" / crate / "README.md").read_bytes()
    files["docs/comparison.md"] = (ROOT / "docs/comparison.md").read_bytes()
    files["docs/public-alpha.md"] = (ROOT / "docs/public-alpha.md").read_bytes()
    files["install.py"] = (ROOT / "scripts/install.py").read_bytes()
    for path in sorted((ROOT / "web/dist").rglob("*")):
        if path.is_file():
            files["web/" + str(path.relative_to(ROOT / "web/dist"))] = path.read_bytes()
    manifest = {"format": 1, "version": version, "target": target,
                "features": ["parallel-compilation"] if parallel_compilation else [],
                "toolchains": {"rustc": run("rustc", "--version"), "node": run("node", "--version"), "npm": run("npm", "--version")},
                "glibc_required": sorted(set(re.findall(r"GLIBC_\d+\.\d+", run("objdump", "-T", str(binary)))), key=lambda v: tuple(map(int, v[6:].split('.'))))[-1],
                "source_sha256": digest(json.dumps(source, sort_keys=True).encode()),
                "files": {name: digest(data) for name, data in sorted(files.items())}}
    identity = digest(json.dumps(manifest, sort_keys=True).encode())[:16]
    manifest["release_id"] = f"{version}-{target}-{identity}"
    files["manifest.json"] = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    archive_name = f"rustwalld-dns-{manifest['release_id']}.tar.gz"
    output.mkdir(parents=True, exist_ok=True)
    # Bytes of identical built inputs are stable: order, owner, mode, time, gzip header.
    with tempfile.NamedTemporaryFile(dir=output, prefix=".release-", delete=False) as temp:
        temporary = Path(temp.name)
        try:
            with gzip.GzipFile(fileobj=temp, mode="wb", filename="", mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                    for name, data in sorted(files.items()):
                        member = tarfile.TarInfo(name)
                        member.size = len(data)
                        member.mode = 0o755 if name in ("bin/rustwalld-dns", "install.py") else 0o644
                        archive.addfile(member, io.BytesIO(data))
            temp.flush()
            os.fsync(temp.fileno())
            os.chmod(temporary, 0o644)
            os.replace(temporary, output / archive_name)
        finally:
            temporary.unlink(missing_ok=True)
    final = output / archive_name
    checksum = digest(final.read_bytes())
    (output / (archive_name + ".sha256")).write_text(f"{checksum}  {archive_name}\n")
    return final


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "target/releases")
    parser.add_argument("--skip-build", action="store_true", help="repack already built inputs; never use stale artifacts for a published build")
    parser.add_argument("--parallel-compilation", action="store_true", help="build/package the optional owned two-worker compiler")
    args = parser.parse_args()
    print(build(args.output, args.skip_build, args.parallel_compilation))
