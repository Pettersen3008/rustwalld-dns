"""Service-manager adapter used only by smoke.py in a fresh disposable VM."""
import atexit
import json
import os
from pathlib import Path
import shutil
import subprocess


UNIT = 'rustwalld-dns.service'
STATE = Path('/var/lib/rustwalld-dns')
PROBE = Path('/usr/local/lib/rustwalld-dns-smoke/probe.py')
DROPIN = Path('/etc/systemd/system/rustwalld-dns.service.d/smoke.conf')
OUTSIDE = Path('/tmp/rustwalld-dns-smoke-outside')
HOME = Path('/home/rustwalld-dns-smoke-visible')


def command(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=30)


class NativeService:
    def __init__(self):
        if os.geteuid() != 0:
            raise PermissionError('native smoke requires root inside a fresh disposable VM')
        command('systemd-detect-virt', '--vm', '--quiet')
        if command('systemd-detect-virt', '--container', '--quiet', check=False).returncode == 0:
            raise ValueError('native smoke requires a full VM, not a container')
        if Path('/proc/1/comm').read_text().strip() != 'systemd':
            raise ValueError('native smoke requires systemd as PID1')
        for name in ('/opt/rustwalld-dns', '/etc/rustwalld-dns', str(STATE),
                     '/usr/lib/systemd/system/' + UNIT, str(DROPIN.parent),
                     '/etc/systemd/system/' + UNIT, '/run/systemd/system/' + UNIT,
                     '/usr/local/lib/systemd/system/' + UNIT,
                     str(PROBE.parent), str(OUTSIDE), str(HOME)):
            path = Path(name)
            if path.exists() or path.is_symlink():
                raise ValueError('native smoke requires absent managed paths: ' + name)
        self.starts = 0
        atexit.register(self.abort)

    @staticmethod
    def abort():
        # Preserve failed guest state/probes while ensuring the service stops.
        command('systemctl', 'stop', UNIT, check=False)
        command('systemctl', 'disable', UNIT, check=False)

    def prepare(self):
        PROBE.parent.mkdir(mode=0o755)
        shutil.copyfile(Path(__file__).with_name('native_probe.py'), PROBE)
        PROBE.chmod(0o644)
        DROPIN.parent.mkdir(mode=0o755)
        DROPIN.write_text('[Service]\nExecStartPost=/usr/bin/python3 ' + str(PROBE) + '\n')
        for path in (OUTSIDE, HOME):
            path.write_text('Visible outside the service sandbox\n')
            path.chmod(0o644)
        command('systemctl', 'daemon-reload')

    def start(self):
        self.starts += 1
        if self.starts > 32:
            raise ValueError('native smoke exceeded its service-start bound')
        command('systemctl', 'start', UNIT)
        properties = command('systemctl', 'show', UNIT,
                             '--property=MainPID,ActiveState,SubState,User,Group,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,ProtectSystem,ProtectHome,PrivateTmp,PrivateDevices,ProtectKernelTunables,ProtectKernelModules,ProtectKernelLogs,ProtectControlGroups,ProtectClock,ProtectHostname,RestrictAddressFamilies,SystemCallFilter,MemoryDenyWriteExecute').stdout
        values = dict(line.split('=', 1) for line in properties.splitlines())
        assert values['ActiveState'] == 'active' and values['SubState'] == 'running'
        assert values['User'] == values['Group'] == 'rustwalld-dns'
        assert values['CapabilityBoundingSet'] == values['AmbientCapabilities'] == ''
        assert values['ProtectSystem'] == 'strict'
        for key in ('NoNewPrivileges', 'ProtectHome', 'PrivateTmp', 'PrivateDevices',
                    'ProtectKernelTunables', 'ProtectKernelModules', 'ProtectKernelLogs',
                    'ProtectControlGroups', 'ProtectClock', 'ProtectHostname', 'MemoryDenyWriteExecute'):
            assert values[key] == 'yes', (key, values[key])
        assert set(values['RestrictAddressFamilies'].split()) == {'AF_UNIX', 'AF_INET', 'AF_INET6'}
        assert values['SystemCallFilter']
        pid = int(values['MainPID'])
        status = Path(f'/proc/{pid}/status').read_text()
        fields = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
        assert fields['NoNewPrivs'].strip() == '1'
        assert int(fields['CapEff'], 16) == int(fields['CapBnd'], 16) == 0
        assert fields['Seccomp'].strip() == '2'
        (STATE / 'native-unit-properties.txt').write_text(properties)
        (STATE / 'native-main-status.txt').write_text(status)
        assert json.loads((STATE / 'native-probe.json').read_text())['passed']
        return pid

    @staticmethod
    def running(pid):
        return Path(f'/proc/{pid}').exists()

    @staticmethod
    def stop(pid):
        command('systemctl', 'stop', UNIT)
        assert not Path(f'/proc/{pid}').exists()

    def close(self):
        command('systemctl', 'stop', UNIT)
        command('systemctl', 'disable', UNIT)
        assert command('systemctl', 'is-active', UNIT, check=False).stdout.strip() == 'inactive'
        assert command('systemctl', 'is-enabled', UNIT, check=False).stdout.strip() == 'disabled'
        (STATE / 'native-security.txt').write_text(command('systemd-analyze', 'security', UNIT).stdout)
        (STATE / 'native-journal.txt').write_text(command('journalctl', '-u', UNIT, '--no-pager', '-o', 'short-iso').stdout)
        for path in (DROPIN, PROBE, OUTSIDE, HOME):
            path.unlink()
        DROPIN.parent.rmdir()
        PROBE.parent.rmdir()
        command('systemctl', 'daemon-reload')
        (STATE / 'native-complete.json').write_text(json.dumps({
            'service_starts': self.starts, 'active': False, 'enabled': False,
            'probe_dropin_removed': True,
        }, indent=2) + '\n')
        atexit.unregister(self.abort)
