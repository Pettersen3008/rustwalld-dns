#!/usr/bin/env python3
"""Check public library contracts from three independent Cargo workspaces."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
for name in ("core", "components", "runtime"):
    manifest = ROOT / "tests/consumers" / name / "Cargo.toml"
    for command in (
        ["cargo", "fmt", "--manifest-path", str(manifest), "--", "--check"],
        ["cargo", "clippy", "--manifest-path", str(manifest), "--all-targets", "--locked",
         "--target-dir", str(ROOT / "target"), "--", "-D", "warnings"],
        ["cargo", "test", "--manifest-path", str(manifest), "--locked", "--target-dir", str(ROOT / "target")],
    ):
        subprocess.run(command, cwd=ROOT, check=True)
