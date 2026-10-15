#!/usr/bin/env python3
"""Emit descriptive source metrics as JSON; this is not a performance benchmark."""
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def inventory(root):
    paths = sorted({*root.glob("crates/**/*.rs"), *root.glob("web/src/**/*.ts"),
                    *root.glob("web/src/**/*.tsx"), *root.glob("web/src/**/*.css")})
    digest = hashlib.sha256()
    rows = []
    for path in paths:
        raw = path.read_bytes()
        name = str(path.relative_to(root))
        digest.update(name.encode() + b"\0" + hashlib.sha256(raw).digest())
        text = raw.decode()
        rows.append({"path": name, "lines": len(text.splitlines()), "bytes": len(raw)})
    rust = [row for row in rows if row["path"].endswith(".rs")]
    frontend = [row for row in rows if row not in rust]
    # Lexical counts intentionally include tests/comments, including inline tests.
    rust_text = "\n".join((root / row["path"]).read_text() for row in rust)
    docs = list((root / "docs").rglob("*.md"))
    return {
        "schema": 1,
        "scope": "Rust crates and web/src; physical lines; lexical counts include tests/comments",
        "source_sha256": digest.hexdigest(),
        "rust": {"files": len(rust), "lines": sum(row["lines"] for row in rust)},
        "frontend": {"files": len(frontend), "lines": sum(row["lines"] for row in frontend)},
        "docs": {"files": len(docs), "bytes": sum(path.stat().st_size for path in docs)},
        "lexical_occurrences": {
            "unwrap": len(re.findall(r"\bunwrap\s*\(", rust_text)),
            "expect": len(re.findall(r"\bexpect\s*\(", rust_text)),
            "unsafe": len(re.findall(r"\bunsafe\b", rust_text)),
            "lint_allow_attributes": len(re.findall(r"#\s*!?\[allow\b", rust_text)),
            "test_attributes": len(re.findall(r"#\[(?:tokio::)?test(?:\([^]]*\))?\]", rust_text)),
        },
        "largest_files": sorted(rows, key=lambda row: (-row["lines"], row["path"]))[:15],
        "files_above_1000_lines": [row for row in rows if row["lines"] > 1000],
    }


def main():
    result = inventory(ROOT)
    result["git_head"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    result["worktree_dirty"] = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT))
    binary = ROOT / "target/release/rustwalld-dns"
    result["existing_release_binary_bytes"] = binary.stat().st_size if binary.exists() else None
    result["binary_note"] = "Existing artifact may be stale; size is not evidence of a current-source build."
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
