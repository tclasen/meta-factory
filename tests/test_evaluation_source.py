"""Explicit source selection keeps generated symlinks out of redeployment."""

import json
from pathlib import Path
import tempfile
import unittest

from evaluation.evidence import Attempt
from evaluation.sandbox import capture_tree
from evaluation.source import capture_source, parse_paths
from test_evaluation_deployment import FakeGuard, FakeSandbox


class SourceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / 'source'
        self.source.mkdir()
        (self.source / '.git').mkdir()
        (self.source / '.git/HEAD').write_text('ref: refs/heads/main\n')
        (self.source / 'app.py').write_text('source\n')
        (self.source / '.gitignore').write_text('.venv/\n')
        (self.source / '.venv').mkdir()
        (self.source / '.venv/python').symlink_to('/usr/bin/python3')
        self.spec = self.root / 'spec'
        self.spec.mkdir()
        FakeGuard.stopped = True

    def test_source_capture_records_ignored_artifacts_and_deleted_tracked_files(self):
        def command(attempt, label, argv, **kwargs):
            self.assertEqual(argv[:2], ['sbx', 'exec'])
            self.assertIn('core.fsmonitor=false', argv)
            output = {'inventory-selected': b'app.py\0.gitignore\0deleted.py\0',
                      'inventory-deleted': b'deleted.py\0',
                      'inventory-ignored': b'.venv/python\0'}[label]
            folder = attempt.directory / label
            folder.mkdir()
            (folder / 'stdout.log').write_bytes(output)
            return {'outcome': 'passed'}
        with Attempt(self.root / 'logs', {}) as attempt:
            result = capture_source(attempt, self.source, self.root / 'capture', self.spec,
                                    port=18080, termination_verified=True,
                                    sandbox_factory=FakeSandbox, guard_factory=FakeGuard,
                                    command_runner=command)
        self.assertEqual(set(result['files']), {'app.py', '.gitignore', '.git/HEAD'})
        self.assertEqual(result['selection']['ignored'], ['.venv/python'])
        self.assertEqual(result['selection']['deleted'], ['deleted.py'])
        self.assertFalse((self.root / 'capture/.venv').exists())
        self.assertEqual((self.root / 'logs/captured-source/app.py').read_text(), 'source\n')
        self.assertEqual(result['unix_modes']['files']['app.py'], self.source.joinpath('app.py').stat().st_mode&0o777)
        saved = json.loads((self.root/'logs/source-capture.json').read_text())
        self.assertEqual(saved['unix_modes'], result['unix_modes'])
        retention = json.loads((self.root / 'logs/source-retention.json').read_text())
        self.assertEqual(retention, {
            'bytes': result['bytes'],
            'files': len(result['files']),
            'relative_path': 'captured-source',
            'verified_against_capture': True,
        })

    def test_selected_symlink_parent_cannot_escape(self):
        (self.source / 'escape').symlink_to(self.root, target_is_directory=True)
        (self.root / 'secret').write_text('private')
        with self.assertRaises(ValueError):
            capture_tree(self.source, self.root / 'capture', termination_verified=True,
                         selected_files=['escape/secret'])
        self.assertFalse((self.root / 'capture').exists())

    def test_missing_selected_file_cannot_silently_disappear(self):
        with self.assertRaises(ValueError):
            capture_tree(self.source, self.root / 'capture', termination_verified=True,
                         selected_files=['missing'])

    def test_inventory_rejects_truncation_traversal_metadata_and_noncanonical_paths(self):
        for data in (b'partial', b'../outside\0', b'/absolute\0', b'.git/config\0', b'a/./b\0'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                parse_paths(data)
        self.assertEqual(parse_paths(b'spaces and\nnewlines\0'), {'spaces and\nnewlines'})

    def test_inventory_refused_before_builder_stop(self):
        with Attempt(self.root / 'logs', {}) as attempt:
            with self.assertRaises(ValueError):
                capture_source(attempt, self.source, self.root / 'capture', self.spec,
                               port=18080, termination_verified=False)
