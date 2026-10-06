#!/usr/bin/env python3
"""Verify an unpacked release, then stage/install without enabling services."""
import argparse
import hashlib
import grp
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import secrets
import shutil
import subprocess
import tempfile


def verify(bundle):
    if bundle.is_symlink() or not bundle.is_dir():
        raise ValueError("bundle must be an ordinary unpacked directory")
    manifest_path = bundle / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file() or manifest_path.stat().st_size > 1024 * 1024:
        raise ValueError("invalid manifest")
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("format") != 1 or not re.fullmatch(r"[0-9][0-9A-Za-z_.-]{2,160}", manifest.get("release_id", "")):
        raise ValueError("unsupported bundle manifest")
    expected = set(manifest["files"]) | {"manifest.json"}
    actual = set()
    for path in bundle.rglob("*"):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError("bundle cannot contain symlinks or special files")
        if path.is_file():
            actual.add(path.relative_to(bundle).as_posix())
    if expected != actual:
        raise ValueError("bundle has missing or unexpected files")
    for name, checksum in manifest["files"].items():
        relative = PurePosixPath(name)
        if relative.is_absolute() or '..' in relative.parts or str(relative) != name:
            raise ValueError("invalid bundle member path")
        if hashlib.sha256((bundle / name).read_bytes()).hexdigest() != checksum:
            raise ValueError(f"checksum mismatch: {name}")
    for required in ("bin/rustwalld-dns", "web/index.html", "config/config.toml", "systemd/rustwalld-dns.service"):
        if required not in expected:
            raise ValueError(f"missing required file: {required}")
    return manifest


def directory(path, mode=0o755):
    missing = []
    parent = path
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for created in reversed(missing):
        created.mkdir()
        created.chmod(0o755)
    path.chmod(mode)


def install(bundle, root):
    manifest = verify(bundle)
    root = root.resolve()
    live = root == Path('/')
    if live and os.geteuid() != 0:
        raise PermissionError("system installation requires root; use --root for a staged test")
    # Managed paths must not redirect root writes through preexisting symlinks.
    for relative in ('opt/rustwalld-dns/releases', 'etc/rustwalld-dns/config.toml', 'etc/rustwalld-dns/service.env', 'var/lib/rustwalld-dns', 'usr/lib/systemd/system/rustwalld-dns.service'):
        path = root / relative
        while path != root:
            if path.is_symlink():
                raise ValueError(f'managed path is a symlink: {path}')
            path = path.parent
    if live:
        try:
            account = pwd.getpwnam('rustwalld-dns')
        except KeyError:
            subprocess.run(['useradd', '--system', '--user-group', '--no-create-home', '--home-dir', '/var/lib/rustwalld-dns', '--shell', '/usr/sbin/nologin', 'rustwalld-dns'], check=True)
            account = pwd.getpwnam('rustwalld-dns')
        if account.pw_uid == 0 or account.pw_gid == 0 or account.pw_uid >= 1000 or account.pw_dir != '/var/lib/rustwalld-dns' or account.pw_shell not in ('/usr/sbin/nologin', '/sbin/nologin'):
            raise ValueError('rustwalld-dns must be a dedicated non-root system account')
        try:
            if grp.getgrnam('rustwalld-dns').gr_gid != account.pw_gid:
                raise ValueError('rustwalld-dns account must use its dedicated service group')
        except KeyError as error:
            raise ValueError('missing dedicated rustwalld-dns service group') from error
    releases = root / 'opt/rustwalld-dns/releases'
    directory(releases.parent)
    directory(releases)
    final = releases / manifest['release_id']
    if final.exists():
        if final.is_symlink() or verify(final) != manifest:
            raise ValueError('installed release content differs from its manifest')
    else:
        with tempfile.TemporaryDirectory(prefix='.install-', dir=releases) as temporary:
            prepared = Path(temporary) / 'release'
            shutil.copytree(bundle, prepared)
            if verify(prepared) != manifest:
                raise ValueError("bundle changed during staging")
            for path in prepared.rglob('*'):
                path.chmod(0o755 if path.is_dir() or path.relative_to(prepared).as_posix() in ('bin/rustwalld-dns', 'install.py') else 0o644)
            prepared.chmod(0o755)
            prepared.rename(final)
    settings = root / 'etc/rustwalld-dns'
    directory(settings, 0o750)
    config = settings / 'config.toml'
    if not config.exists():
        with config.open('x') as stream:
            stream.write((final / 'config/config.toml').read_text())
    config.chmod(0o640)
    secret = settings / 'service.env'
    if not secret.exists():
        fd = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(f'RUSTWALLD_API_TOKEN={secrets.token_hex(32)}\n')
    secret.chmod(0o600)
    state = root / 'var/lib/rustwalld-dns'
    directory(state, 0o750)
    if live:
        os.chown(settings, 0, account.pw_gid)
        os.chown(config, 0, account.pw_gid)
        os.chown(secret, 0, 0)
        os.chown(state, account.pw_uid, account.pw_gid)
    unit_dir = root / 'usr/lib/systemd/system'
    directory(unit_dir)
    unit = unit_dir / 'rustwalld-dns.service'
    with tempfile.NamedTemporaryFile(dir=unit_dir, delete=False) as stream:
        temporary_unit = Path(stream.name)
        try:
            stream.write((final / 'systemd/rustwalld-dns.service').read_bytes())
            stream.flush()
            os.fsync(stream.fileno())
            temporary_unit.chmod(0o644)
            temporary_unit.replace(unit)
        finally:
            temporary_unit.unlink(missing_ok=True)
    current = releases.parent / 'current'
    temporary_link = releases.parent / ('.current-' + secrets.token_hex(8))
    try:
        temporary_link.symlink_to('releases/' + manifest['release_id'])
        temporary_link.replace(current)
    finally:
        temporary_link.unlink(missing_ok=True)
    return final


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle', type=Path, help='trusted, unpacked release directory')
    parser.add_argument('--root', type=Path, default=Path('/'), help='stage in an isolated root without creating users or touching host services')
    args = parser.parse_args()
    print(install(args.bundle, args.root))
    print('Review config; run systemctl daemon-reload and enable/start explicitly on the target host.')
