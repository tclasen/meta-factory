"""Recovery uses exact recorded identities and preserves original evidence."""

import json
from pathlib import Path
import tempfile
import unittest

from evaluation.evidence import Attempt, atomic_json
from evaluation.recovery import recover, resources, state_from_listing


class RecoveryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'original'
        self.name = 'factory-eval-builder-0123456789abcdef'
        with Attempt(self.source, {}) as attempt:
            atomic_json(self.source / 'builder-resource.json',
                        {'name': self.name, 'manual_stop': ['sbx', 'stop', self.name]})
            attempt.emit('controller', 'command.start', {'check': 'builder-create',
                         'argv': ['sbx', 'create', '--name', self.name]})

    def test_running_recorded_resource_stopped_and_unrelated_resource_untouched(self):
        commands = []
        original = (self.source / 'events.jsonl').read_bytes()
        def command(attempt, label, argv, **kwargs):
            commands.append(argv)
            if argv == ['sbx', 'ls']:
                state = 'running' if label.endswith('before') else 'stopped'
                folder = attempt.directory / label; folder.mkdir()
                (folder / 'stdout.log').write_text('SANDBOX AGENT STATUS\n' +
                    f'{self.name} codex {state}\nunrelated codex running\n')
            return {'outcome': 'passed'}
        with Attempt(self.root / 'recovery', {}) as attempt:
            result = recover(attempt, self.source, command_runner=command)
        self.assertEqual(result['outcome'], 'cleanup_verified')
        self.assertEqual(commands, [['sbx', 'ls'], ['sbx', 'stop', self.name], ['sbx', 'ls']])
        self.assertEqual((self.source / 'events.jsonl').read_bytes(), original)
        self.assertFalse(result['resumed'])

    def test_absent_resource_is_safe_without_stop_or_restart(self):
        def command(attempt, label, argv, **kwargs):
            self.assertEqual(argv, ['sbx', 'ls'])
            folder = attempt.directory / label; folder.mkdir()
            (folder / 'stdout.log').write_text('SANDBOX AGENT STATUS\nunrelated codex running\n')
            return {'outcome': 'passed'}
        with Attempt(self.root / 'recovery', {}) as attempt:
            result = recover(attempt, self.source, command_runner=command)
        self.assertEqual(result['resources'][self.name]['after'], 'absent')
        self.assertEqual(result['outcome'], 'cleanup_verified')

    def test_daemon_unavailable_never_proves_cleanup(self):
        with Attempt(self.root / 'recovery', {}) as attempt:
            result = recover(attempt, self.source, command_runner=lambda *a, **kw: {'outcome': 'failed'})
        self.assertEqual(result['outcome'], 'cleanup_incomplete')

    def test_name_record_without_matching_creation_is_rejected(self):
        (self.source / 'events.jsonl').write_text('')
        with self.assertRaises(ValueError): resources(self.source)

    def test_unrelated_name_and_symlink_records_rejected(self):
        path = self.source / 'builder-resource.json'
        record = json.loads(path.read_text()); record['name'] = 'unrelated'
        path.write_text(json.dumps(record))
        with self.assertRaises(ValueError): resources(self.source)
        path.unlink(); path.symlink_to(self.root / 'other')
        with self.assertRaises(ValueError): resources(self.source)

    def test_unknown_listing_does_not_mean_absent(self):
        with self.assertRaises(ValueError): state_from_listing('daemon unavailable', self.name)
