"""Scoped source reads preserve lifetime/configuration refusal without repeated content reads."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from evaluation.evidence import atomic_json
from evaluation.fixture_lifetime import FixtureLifetime
from evaluation.preparation import read_regular
from evaluation.source_binding import SourceBinding
from evaluation.verdicts import Inconclusive


class FixtureLifetimeScopeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.project = self.root / 'project'
        self.project.mkdir()
        self.directory = self.root / 'guard'
        self.directory.mkdir()
        self.box = SimpleNamespace(name='factory-eval-grader-0123456789abcdef',
            project=self.project, specification=self.root / 'spec',
            creation_attempted=True, stopped=False)
        self.guard = SimpleNamespace(directory=self.directory,
            process=SimpleNamespace(poll=lambda: None), nonce='0'*32)
        self.config = self.directory / 'config.json'
        atomic_json(self.config, dict(schema_version=1, sandbox=self.box.name,
            owner_pid=os.getpid(), nonce=self.guard.nonce, max_seconds=1000,
            expires_at=1000))
        self.clock = 100
        self.lifetime = FixtureLifetime(self.box, self.guard,
            monotonic_deadline=900, wall_deadline=900,
            monotonic=lambda: self.clock, wall=lambda: self.clock)

    def binding(self, count=1):
        expected = {}
        for index in range(count):
            path = self.project / (str(index) + '.py')
            data = b'# independently captured source\n' * 2500
            path.write_bytes(data)
            expected[path.name] = dict(size=len(data), executable=False,
                sha256=hashlib.sha256(data).hexdigest())
        return SourceBinding(self.project, expected,
            lifetime_check=self.lifetime.check, lifetime_scope=self.lifetime.read_scope)

    def test_full_configuration_reads_are_constant_across_many_source_files_and_chunks(self):
        binding = self.binding(30)
        with patch('evaluation.fixture_lifetime.read_regular', wraps=read_regular) as reader:
            self.assertIs(binding.check(10), True)
        self.assertEqual(reader.call_count, 4)

    def test_scope_check_cannot_escape_its_scope(self):
        with self.lifetime.read_scope(10) as check:
            self.assertIs(check(10), True)
        with self.assertRaises(Inconclusive):
            check()

    def test_write_restore_and_identical_inode_replacement_refuse_during_read(self):
        original = self.config.read_bytes()
        for mode in ('write-restore', 'replace'):
            with self.subTest(mode=mode), self.assertRaises(Inconclusive):
                with self.lifetime.read_scope() as check:
                    if mode == 'write-restore':
                        self.config.write_bytes(b'changed configuration')
                        self.config.write_bytes(original)
                    else:
                        replacement = self.directory / 'replacement'
                        replacement.write_bytes(original)
                        os.replace(replacement, self.config)
                    check()

    def test_guard_stop_release_owner_scope_and_clock_loss_refuse_inside_scope(self):
        mutations = [lambda: setattr(self.box, 'stopped', True),
                     lambda: setattr(self.guard.process, 'poll', lambda: 0),
                     lambda: setattr(self.box, 'name', 'factory-eval-grader-fedcba9876543210'),
                     lambda: setattr(self, 'clock', 900),
                     lambda: (self.directory / 'release.json').write_text('{}')]
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(Inconclusive):
                with self.lifetime.read_scope() as check:
                    mutation()
                    check()
            self.box.stopped = False
            self.box.name = 'factory-eval-grader-0123456789abcdef'
            self.guard.process.poll = lambda: None
            self.clock = 100
            (self.directory / 'release.json').unlink(missing_ok=True)
        with self.assertRaises(Inconclusive), self.lifetime.read_scope() as check:
            with patch('evaluation.fixture_lifetime.os.getpid', return_value=os.getpid()+1):
                check()

    def test_configuration_is_checked_on_exceptional_exit(self):
        with patch('evaluation.fixture_lifetime.read_regular', wraps=read_regular) as reader:
            with self.assertRaisesRegex(RuntimeError, 'operator failure'):
                with self.lifetime.read_scope():
                    raise RuntimeError('operator failure')
        self.assertEqual(reader.call_count, 2)

    def test_ancestor_symlink_replacement_is_refused_at_scope_exit(self):
        with self.assertRaises(Inconclusive):
            with self.lifetime.read_scope():
                moved = self.root / 'original-guard'
                self.directory.rename(moved)
                self.directory.symlink_to(moved, target_is_directory=True)

    def test_source_corruption_and_expiry_during_scoped_read_refuse(self):
        binding = self.binding()
        source = self.project / '0.py'
        original = source.read_bytes()
        original_read = os.read
        for mode in ('corrupt', 'expire'):
            source.write_bytes(original)
            self.clock = 100
            changed = False
            def read(descriptor, count):
                nonlocal changed
                value = original_read(descriptor, count)
                if not changed:
                    changed = True
                    if mode == 'corrupt': source.write_bytes(b'x' * len(original))
                    else: self.clock = 900
                return value
            with self.subTest(mode=mode), patch('evaluation.source_binding.os.read', side_effect=read):
                with self.assertRaises(Inconclusive):
                    binding.check()

    def test_invalid_scopes_and_nontrue_scoped_checks_refuse(self):
        binding = self.binding()
        for invalid in (1, False, 'scope'):
            with self.assertRaises(ValueError):
                SourceBinding(self.project, binding.expected,
                    lifetime_check=self.lifetime.check, lifetime_scope=invalid)
        for value in (1, False, None, 'true'):
            @contextmanager
            def scope(reserve):
                yield lambda amount: value
            binding.lifetime_scope = scope
            with self.assertRaises(Inconclusive):
                binding.check()
        @contextmanager
        def bad_scope(reserve):
            yield None
        binding.lifetime_scope = bad_scope
        with self.assertRaises(ValueError):
            binding.check()


if __name__ == '__main__': unittest.main()
