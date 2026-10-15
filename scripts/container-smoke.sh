#!/usr/bin/env bash
set -euo pipefail
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ $# != 1 ]]; then echo 'usage: scripts/container-smoke.sh VERIFIED_IMAGE:TAG' >&2; exit 2; fi
mkdir -p "$repository/target"
staging=$(mktemp -d "$repository/target/container-smoke.XXXXXX")
trap 'rm -rf -- "$staging"' EXIT
cp "$repository/packaging/container-smoke.py" "$staging/"
cp "$repository/web/e2e/fixtures/download-cert.pem" "$staging/cert.pem"
cp "$repository/web/e2e/fixtures/download-key.pem" "$staging/key.pem"
docker build --build-arg "RELEASE_IMAGE=$1" --file "$repository/packaging/container-smoke.Dockerfile" --tag rustwalld-container-smoke:local "$staging"
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 64 --memory 512m --tmpfs /tmp:size=128m,mode=1777 rustwalld-container-smoke:local
