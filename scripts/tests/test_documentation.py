import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


docs = load("check-docs")
metrics = load("metrics")


class Documentation(unittest.TestCase):
    def test_links_detect_missing_files_and_anchors_but_ignore_fenced_examples(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.md").write_text(
                '# Start\n[valid](b.md#same-1) [gone](missing.md)\n'
                '[bad](b.md#absent) [web](https://example.test/no-network)\n'
                '```md\n[example](also-missing.md)\n```\n'
                '[space](<space name.md>)\n[ref]: b.md#same\n'
            )
            (root / "b.md").write_text('# Same\n## Same\n')
            (root / "space name.md").write_text('# Space\n')
            (root / "target").mkdir()
            (root / "target/ignored.md").write_text('[bad](missing.md)')
            files, errors = docs.check(root)
            self.assertEqual(len(files), 3)
            self.assertEqual(len(errors), 2)
            self.assertIn('a.md:2: missing missing.md', errors)
            self.assertIn('a.md:3: missing heading b.md#absent', errors)

    def test_source_digest_changes_with_content_and_counts_are_descriptive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'crates/example/src/lib.rs'
            path.parent.mkdir(parents=True)
            path.write_text('#[test]\nfn fixture() { value.unwrap(); }\n')
            before = metrics.inventory(root)
            self.assertEqual(before['rust']['lines'], 2)
            self.assertEqual(before['lexical_occurrences']['unwrap'], 1)
            self.assertEqual(before['lexical_occurrences']['test_attributes'], 1)
            path.write_text('pub fn api() {}\n')
            self.assertNotEqual(before['source_sha256'], metrics.inventory(root)['source_sha256'])


if __name__ == '__main__':
    unittest.main()
