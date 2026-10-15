#!/usr/bin/env python3
"""Check repository Markdown file and heading links without network access."""
import argparse
import os
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
IGNORED = {".git", "target", "node_modules", "dist", "test-results", "playwright-report", "__pycache__"}


def markdown_files(root):
    for directory, children, files in os.walk(root):
        children[:] = sorted(name for name in children if name not in IGNORED and not name.startswith(".tmp"))
        for name in sorted(files):
            if name.endswith(".md"):
                yield Path(directory) / name


def prose(text):
    """Ignore fenced examples, where links and headings are literal content."""
    lines = []
    fence = None
    for line in text.splitlines():
        match = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if match:
            marker = match[1]
            if fence is None:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence):
                fence = None
            lines.append("")
        else:
            lines.append(line if fence is None else "")
    return "\n".join(lines)


def anchors(text):
    found = set()
    counts = {}
    for line in prose(text).splitlines():
        match = re.match(r"^#{1,6}\s+(.+?)(?:\s+#+)?$", line)
        if not match:
            continue
        title = re.sub(r"\[([^]]+)\]\([^)]*\)", r"\1", match[1])
        slug = re.sub(r"[^\w\- ]", "", title.lower()).replace(" ", "-")
        count = counts.get(slug, 0)
        counts[slug] = count + 1
        found.add(slug if count == 0 else f"{slug}-{count}")
    found.update(re.findall(r'<(?:a|h[1-6])\b[^>]*\bid=["\']([^"\']+)', text))
    return found


def links(text):
    # Repository conventions use inline links and optional reference definitions.
    # Angle destinations allow spaces; parentheses are escaped when in a path.
    pattern = r'!?\[[^\]\n]*\]\(\s*(<[^>\n]+>|[^\s)]+)(?:\s+["\'][^\n]*?["\'])?\s*\)'
    for line_number, line in enumerate(prose(text).splitlines(), 1):
        for match in re.finditer(pattern, line):
            yield line_number, match[1].strip("<>")
        match = re.match(r"^\s{0,3}\[[^]]+\]:\s*(<[^>]+>|\S+)", line)
        if match:
            yield line_number, match[1].strip("<>")


def check(root):
    errors = []
    files = list(markdown_files(root))
    headings = {}
    for source in files:
        for line, destination in links(source.read_text()):
            url = urlsplit(destination)
            if url.scheme or url.netloc:
                continue
            path = unquote(url.path)
            target = (source.parent / path).resolve() if path else source.resolve()
            if not target.exists():
                errors.append(f"{source.relative_to(root)}:{line}: missing {destination}")
            elif url.fragment and target.suffix == ".md":
                if target not in headings:
                    headings[target] = anchors(target.read_text())
                if unquote(url.fragment) not in headings[target]:
                    errors.append(f"{source.relative_to(root)}:{line}: missing heading {destination}")
    return files, errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    files, errors = check(args.root.resolve())
    for error in errors:
        print(error, file=sys.stderr)
    print(f"Checked {len(files)} Markdown files; {len(errors)} broken local links.")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
