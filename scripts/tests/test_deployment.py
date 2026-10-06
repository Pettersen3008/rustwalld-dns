import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / f'{name}.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


installer = module('install')
release = module('release')


def fixture(path, identity='0.1.0-x86_64-unknown-linux-gnu-0123456789abcdef'):
    files = {'bin/rustwalld-dns': b'fixture', 'web/index.html': b'local ui', 'config/config.toml': b'dns_listen="127.0.0.1:5353"\n', 'systemd/rustwalld-dns.service': b'[Service]\nUser=rustwalld-dns\n'}
    path.mkdir()
    for name, content in files.items():
        file = path / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(content)
    manifest = {'format': 1, 'release_id': identity, 'files': {name: hashlib.sha256(value).hexdigest() for name, value in files.items()}}
    (path / 'manifest.json').write_text(json.dumps(manifest))
    return path


class Deployment(unittest.TestCase):
    def test_staged_upgrade_preserves_config_secret_state_and_old_release(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'target') as directory:
            directory = Path(directory)
            bundle = fixture(directory / 'bundle')
            root = directory / 'stage'
            first = installer.install(bundle, root)
            config = root / 'etc/rustwalld-dns/config.toml'
            secret = root / 'etc/rustwalld-dns/service.env'
            config.write_text('custom-config\n')
            state = root / 'var/lib/rustwalld-dns/keep.txt'
            state.write_text('keep')
            saved_token = secret.read_bytes()
            second = fixture(directory / 'upgrade', '0.1.1-x86_64-unknown-linux-gnu-fedcba9876543210')
            final = installer.install(second, root)
            self.assertEqual((root / 'opt/rustwalld-dns/current').resolve(), final)
            self.assertTrue(first.is_dir())
            self.assertEqual(config.read_text(), 'custom-config\n')
            self.assertEqual(secret.read_bytes(), saved_token)
            self.assertEqual(secret.stat().st_mode & 0o777, 0o600)
            self.assertEqual(state.read_text(), 'keep')
            installer.install(second, root)  # Idempotent reinstallation.

    def test_restrictive_umask_cannot_hide_release_from_the_service_user(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'target') as directory:
            directory = Path(directory)
            bundle = fixture(directory / 'bundle')
            root = directory / 'stage'
            previous = os.umask(0o077)
            try:
                final = installer.install(bundle, root)
            finally:
                os.umask(previous)
            for path in (root / 'opt', final.parent.parent, final.parent, final, final / 'bin'):
                self.assertEqual(path.stat().st_mode & 0o777, 0o755)
            self.assertEqual((root / 'etc/rustwalld-dns/config.toml').stat().st_mode & 0o777, 0o640)
            self.assertEqual((root / 'etc/rustwalld-dns/service.env').stat().st_mode & 0o777, 0o600)

    def test_tampering_unlisted_files_and_symlinks_are_rejected_before_install(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'target') as directory:
            directory = Path(directory)
            bundle = fixture(directory / 'bundle')
            (bundle / 'web/index.html').write_bytes(b'tampered')
            with self.assertRaises(ValueError):
                installer.install(bundle, directory / 'stage')
            self.assertFalse((directory / 'stage').exists())
            (bundle / 'web/index.html').write_bytes(b'local ui')
            extra = bundle / 'extra'
            extra.write_text('unexpected')
            with self.assertRaises(ValueError):
                installer.verify(bundle)
            extra.unlink()
            (bundle / 'web/index.html').unlink()
            (bundle / 'web/index.html').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError):
                installer.verify(bundle)

    def test_staged_destination_symlinks_do_not_modify_other_directories(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'target') as directory:
            directory = Path(directory)
            bundle = fixture(directory / 'bundle')
            root = directory / 'stage'
            root.mkdir()
            elsewhere = directory / 'elsewhere'
            elsewhere.mkdir()
            (root / 'etc').symlink_to(elsewhere)
            with self.assertRaises(ValueError):
                installer.install(bundle, root)
            self.assertEqual(list(elsewhere.iterdir()), [])

    def test_repacking_built_inputs_is_byte_identical_and_manifest_matches(self):
        if not (ROOT / 'target/release/rustwalld-dns').exists() or not (ROOT / 'web/dist/index.html').exists():
            self.fail('build release binary and UI before deployment tests')
        with tempfile.TemporaryDirectory(dir=ROOT / 'target') as directory:
            directory = Path(directory)
            first = release.build(directory, skip_build=True)
            content = first.read_bytes()
            second = release.build(directory, skip_build=True)
            self.assertEqual(first, second)
            self.assertEqual(content, second.read_bytes())
            bundle = directory / 'unpacked'
            bundle.mkdir()
            with tarfile.open(first) as archive:
                archive.extractall(bundle, filter='data')
            manifest = installer.verify(bundle)
            self.assertEqual(manifest['target'], 'x86_64-unknown-linux-gnu' if os.uname().machine == 'x86_64' else 'aarch64-unknown-linux-gnu')
            self.assertTrue((bundle / 'bin/rustwalld-dns').stat().st_mode & 0o111)
            self.assertEqual(manifest['features'], [])
            # Explicit prebuilt mode identifies a distinct installable bundle;
            # caller must supply the corresponding freshly built executable.
            optional = release.build(directory, skip_build=True, parallel_compilation=True)
            self.assertNotEqual(first, optional)
            enabled = directory / 'optional'
            enabled.mkdir()
            with tarfile.open(optional) as archive:
                archive.extractall(enabled, filter='data')
            self.assertEqual(installer.verify(enabled)['features'], ['parallel-compilation'])


if __name__ == '__main__':
    unittest.main()
