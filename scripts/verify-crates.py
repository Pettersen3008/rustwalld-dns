#!/usr/bin/env python3
"""Verify library archives and public consumers without publishing anything."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = [f"rustwalld-dns-{name}" for name in ("filter", "resolver", "policy", "core", "runtime")]


def run(command):
    subprocess.run(command, cwd=ROOT, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-dirty", action="store_true", help="verify work in progress")
    parser.add_argument("--offline", action="store_true", help="use cached dependencies")
    args = parser.parse_args()
    target = ROOT / "target"
    target.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="crate-check-", dir=target) as temporary:
        staging = Path(temporary)
        command = ["cargo", "package", "--locked", "--target-dir", str(staging / "build")]
        for package in PACKAGES:
            command += ["-p", package]
        if args.allow_dirty:
            command.append("--allow-dirty")
        if args.offline:
            command.append("--offline")
        # Cargo verifies the whole selected graph with a temporary local registry.
        # Do not use --no-verify: package success includes compiled archive contents.
        run(command)
        report = {"archives": {}, "consumers": []}
        extracted = staging / "sources"
        extracted.mkdir()
        for package in PACKAGES:
            archives = list((staging / "build/package").glob(f"{package}-*.crate"))
            if len(archives) != 1:
                raise ValueError(f"expected one archive for {package}")
            archive = archives[0]
            with tarfile.open(archive) as tar:
                names = [member.name for member in tar.getmembers()]
                for member in tar.getmembers():
                    path = Path(member.name)
                    if not member.isfile() or path.is_absolute() or ".." in path.parts:
                        raise ValueError("archive must contain ordinary relative files")
                    if any(part in {"node_modules", "target", ".git"} for part in path.parts):
                        raise ValueError("generated material in library archive")
                for required in ("README.md", "LICENSE-MIT", "LICENSE-APACHE", "Cargo.toml", "src/lib.rs"):
                    if f"{archive.stem}/{required}" not in names:
                        raise ValueError(f"missing {required} in {package}")
                tar.extractall(extracted, filter="data")
            report["archives"][package] = {
                "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(), "files": len(names),
            }
        patches = "\n[patch.crates-io]\n"
        for package in PACKAGES:
            source = next(extracted.glob(f"{package}-*"))
            patches += f'{package} = {{ path = {json.dumps(str(source))} }}\n'
        for name in ("core", "components", "runtime"):
            source = ROOT / "tests/consumers" / name
            consumer = staging / "consumers" / name
            shutil.copytree(source, consumer, ignore=shutil.ignore_patterns("Cargo.lock", "target"))
            manifest = consumer / "Cargo.toml"
            text = re.sub(r'path = "../../../crates/[^\"]+"', 'version = "0.1.0"', manifest.read_text())
            manifest.write_text(text + patches)
            command = ["cargo", "test", "--manifest-path", str(manifest), "--target-dir", str(target)]
            if args.offline:
                command.append("--offline")
            run(command)
            report["consumers"].append(name)
        (target / "crate-verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print("All five library archives and three independent consumers verified.")


if __name__ == "__main__":
    main()
