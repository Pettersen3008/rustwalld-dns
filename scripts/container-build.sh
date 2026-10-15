#!/usr/bin/env bash
set -euo pipefail
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ $# != 2 ]]; then
    echo 'usage: scripts/container-build.sh RELEASE.tar.gz IMAGE:TAG' >&2
    exit 2
fi
archive=$(realpath -- "$1")
if [[ -f "$repository/packaging/Dockerfile" ]]; then
    homelab_dockerfile="$repository/packaging/Dockerfile"
    homelab_installer="$repository/scripts"
else
    homelab_dockerfile="$repository/container/Dockerfile"
    homelab_installer="$repository"
fi
mkdir -p "$repository/target"
staging=$(mktemp -d "$repository/target/container-build.XXXXXX")
trap 'rm -rf -- "$staging"' EXIT
python3 - "$archive" "$staging" "$homelab_installer" <<'PY'
from pathlib import PurePosixPath
import sys,tarfile
sys.path.insert(0,sys.argv[3])
from install import verify
with tarfile.open(sys.argv[1]) as archive:
    for member in archive.getmembers():
        path=PurePosixPath(member.name)
        if not member.isfile() or path.is_absolute() or '..' in path.parts:
            raise ValueError('release archive must contain only ordinary relative files')
    archive.extractall(sys.argv[2],filter='data')
verify(__import__('pathlib').Path(sys.argv[2]))
PY
docker build --file "$homelab_dockerfile" --tag "$2" "$staging"
