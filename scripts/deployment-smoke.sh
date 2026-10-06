#!/usr/bin/env bash
set -euo pipefail
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ $# != 1 ]]; then
    echo 'usage: scripts/deployment-smoke.sh target/releases/RELEASE.tar.gz' >&2
    exit 2
fi
archive=$(realpath -- "$1")
mkdir -p "$repository/target"
staging=$(mktemp -d "$repository/target/deployment-smoke.XXXXXX")
trap 'rm -rf -- "$staging"' EXIT
python3 - "$archive" "$staging" <<'PY'
from pathlib import PurePosixPath
import sys
import tarfile
with tarfile.open(sys.argv[1]) as archive:
    for member in archive.getmembers():
        path = PurePosixPath(member.name)
        if not member.isfile() or path.is_absolute() or '..' in path.parts:
            raise ValueError('release archive must contain only ordinary relative files')
    archive.extractall(sys.argv[2], filter='data')
PY
docker build -f "$repository/packaging/smoke.Dockerfile" -t rustwalld-dns-smoke:local "$repository/packaging"
docker run --rm --network none --mount "type=bind,src=$staging,dst=/bundle,readonly" rustwalld-dns-smoke:local
