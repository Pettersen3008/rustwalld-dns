"""Run by ExecStartPost with the same sandbox settings as the DNS process."""
import errno
import json
import os
from pathlib import Path
import socket
import tempfile


state = Path('/var/lib/rustwalld-dns')
status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
assert os.getuid() != 0 and os.getgid() != 0
assert status['NoNewPrivs'].strip() == '1'
assert int(status['CapEff'], 16) == int(status['CapBnd'], 16) == 0
assert status['Seccomp'].strip() == '2'
assert not Path('/tmp/rustwalld-dns-smoke-outside').exists()
try:
    assert not Path('/home/rustwalld-dns-smoke-visible').exists()
except PermissionError:
    pass
assert not Path('/dev/vda').exists()
mounts = [(parts[4], parts[5].split(',')) for line in Path('/proc/self/mountinfo').read_text().splitlines() if (parts := line.split())]


def options(path):
    matched = [(mount, flags) for mount, flags in mounts if str(path) == mount or str(path).startswith(mount.rstrip('/') + '/')]
    return max(matched, key=lambda item: len(item[0]))[1]


for path in ('/etc/rustwalld-dns', '/opt/rustwalld-dns', '/usr'):
    assert 'ro' in options(path), (path, options(path))
assert 'rw' in options(state)
assert Path('/etc/rustwalld-dns/config.toml').read_text()
for name in ('/etc/rustwalld-dns/config.toml', '/opt/rustwalld-dns/current/bin/rustwalld-dns',
             '/usr/lib/systemd/system/rustwalld-dns.service'):
    try:
        with open(name, 'r+b'):
            raise AssertionError('sandbox permitted protected write: ' + name)
    except OSError as error:
        assert error.errno in (errno.EACCES, errno.EROFS)
try:
    Path('/etc/rustwalld-dns/service.env').read_bytes()
    raise AssertionError('sandbox permitted credential-file read')
except PermissionError:
    pass
with tempfile.TemporaryFile(dir=state) as stream:
    stream.write(b'private state write')
with tempfile.TemporaryFile(dir='/tmp') as stream:
    stream.write(b'private temporary write')
try:
    with socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, 0):
        raise AssertionError('sandbox permitted unlisted address family')
except OSError as error:
    assert error.errno in (errno.EAFNOSUPPORT, errno.EPERM, errno.EACCES)
(state / 'native-probe.json').write_text(json.dumps({
    'passed': True, 'uid': os.getuid(), 'gid': os.getgid(),
    'capabilities': 'empty', 'no_new_privileges': True, 'seccomp': True,
    'protected_mounts_read_only': True, 'state_writable': True,
    'private_tmp': True, 'protected_home': True, 'private_devices': True,
    'unlisted_address_family_denied': True,
}, indent=2) + '\n')
